using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using KnowThankYew.Privacy.Telemetry.Core;

namespace KnowThankYew.Privacy.Telemetry.OpenTelemetry;

public static class PrivacyActivityEnricher
{
    private const string BurnCheckPropertyName = "KnowThankYew.Privacy.BurnCheck";
    private const string PropagationPolicyPropertyName = "KnowThankYew.Privacy.PropagationPolicy";
    private static readonly SafeAllowlist DefaultFailClosedAllowlist = new();
    private static readonly object PropagatorSync = new();
    private static readonly object ActiveDispatchSync = new();
    private static readonly List<ExporterDispatchLease> ActiveDispatches = new();
    private static readonly object WaitGraphSync = new();
    private static readonly Dictionary<object, Dictionary<object, int>> WaitEdges =
        new(ReferenceEqualityComparer.Instance);
    private static readonly ConditionalWeakTable<object, object> BurnedOwners = new();
    private static readonly object BurnedOwnerSentinel = new();
    private static readonly ConditionalWeakTable<object, List<Action<object>>> OwnerPurgeActions = new();
    private static readonly ConditionalWeakTable<object, ConditionalWeakTable<Activity, object>> OwnedActivities = new();
    [ThreadStatic]
    private static AncestorLeaseNode? t_currentAncestorDispatches;

    [ThreadStatic]
    private static PurgeWaitNode? t_currentPurgeHolders;
    [ThreadStatic]
    private static HashSet<ExporterDispatchLease>? _checkingBurnLeases;

    private static readonly Func<bool>[] AlwaysBurnedChecks = new Func<bool>[] { static () => true };

    private sealed class BurnAttachment(Func<bool>[] checks, object[]? owners)
    {
        public Func<bool>[] Checks { get; } = checks;
        public object[]? Owners { get; } = owners;

        public bool IsBurned()
        {
            foreach (var check in Checks)
            {
                if (check())
                {
                    return true;
                }
            }
            return false;
        }
    }

    private sealed class PropagationPolicy(SafeAllowlist allowlist, bool allowRawPayloads, bool isRejected)
    {
        public SafeAllowlist Allowlist { get; } = allowlist;
        public bool AllowRawPayloads { get; } = allowRawPayloads;
        public bool IsRejected { get; } = isRejected;
    }

    private static object[]? MergeOwners(object[]? existing, object? added)
    {
        if (added is null)
        {
            return existing;
        }
        if (existing is null || existing.Length == 0)
        {
            return new[] { added };
        }
        foreach (var item in existing)
        {
            if (ReferenceEquals(item, added))
            {
                return existing;
            }
        }
        var combined = new object[existing.Length + 1];
        Array.Copy(existing, combined, existing.Length);
        combined[existing.Length] = added;
        return combined;
    }

    private static Func<bool>[] MergeChecks(Func<bool>[]? existing, Func<bool> added)
    {
        if (existing is null || existing.Length == 0)
        {
            return new[] { added };
        }
        foreach (var item in existing)
        {
            if (ReferenceEquals(item, added))
            {
                return existing;
            }
        }
        var combined = new Func<bool>[existing.Length + 1];
        Array.Copy(existing, combined, existing.Length);
        combined[existing.Length] = added;
        return combined;
    }

    private static bool HasOwner(object[]? owners, object serviceOwner)
    {
        if (owners is null)
        {
            return false;
        }
        foreach (var item in owners)
        {
            if (ReferenceEquals(item, serviceOwner))
            {
                return true;
            }
        }
        return false;
    }

    private static bool IsAnyOwnerBurnedLocked(object[]? owners)
    {
        if (owners is null)
        {
            return false;
        }
        foreach (var item in owners)
        {
            if (BurnedOwners.TryGetValue(item, out _))
            {
                return true;
            }
        }
        return false;
    }

    private static bool HasDisallowedExternalPublicationOwner(object[]? owners)
    {
        if (owners is null)
        {
            return false;
        }
        foreach (var item in owners)
        {
            if (item is PrivacyTelemetryService service && !service.AllowsExternalActivityPublication)
            {
                return true;
            }
        }
        return false;
    }

    private static bool HasAllowedExternalPublicationOwner(object[]? owners)
    {
        if (owners is null)
        {
            return false;
        }
        foreach (var item in owners)
        {
            if (item is PrivacyTelemetryService service && service.AllowsExternalActivityPublication)
            {
                return true;
            }
        }
        return false;
    }

    private static readonly System.Text.RegularExpressions.Regex StrictTraceParentRegex = new(
        @"^00-(?!0{32})[0-9a-f]{32}-(?!0{16})[0-9a-f]{16}-[0-9a-f]{2}$",
        System.Text.RegularExpressions.RegexOptions.Compiled,
        TimeSpan.FromMilliseconds(100));

    private static object[] CombineOwnerObjects(object[]? existing, object added)
    {
        if (existing is null || existing.Length == 0)
        {
            return new[] { added };
        }
        if (HasOwner(existing, added))
        {
            return existing;
        }
        var combined = new object[existing.Length + 1];
        Array.Copy(existing, combined, existing.Length);
        combined[existing.Length] = added;
        return combined;
    }

    private static bool IsPredicateBurnedSafe(Func<bool>? isBurned)
    {
        if (isBurned is null)
        {
            return false;
        }
        try
        {
            return isBurned();
        }
        catch
        {
            // Fail closed if reading external burn state throws (e.g., disposed session state).
            return true;
        }
    }

    private readonly record struct PropagationHierarchyState(
        object[]? Owners,
        bool IsRejected,
        bool HasAnyPolicy,
        bool AllPoliciesAllowRaw,
        SafeAllowlist? Allowlist);

    private static object[]? ResolveHierarchyOwners(Activity? activity)
    {
        if (activity is null)
        {
            return null;
        }

        object[]? owners = null;
        var depth = 0;
        for (var current = activity; current is not null && depth < 64; current = current.Parent, depth++)
        {
            var attachedOwners = (current.GetCustomProperty(BurnCheckPropertyName) as BurnAttachment)?.Owners;
            if (attachedOwners is not null)
            {
                foreach (var owner in attachedOwners)
                {
                    owners = MergeOwners(owners, owner);
                }
            }
        }
        return owners;
    }

    private static PropagationHierarchyState ResolvePropagationHierarchyState(Activity? activity)
    {
        if (activity is null)
        {
            return new PropagationHierarchyState(null, false, false, false, null);
        }

        object[]? owners = null;
        var isRejected = false;
        var hasAnyPolicy = false;
        var allPoliciesAllowRaw = true;
        SafeAllowlist? allowlist = null;

        var depth = 0;
        var current = activity;
        for (; current is not null && depth < 64; current = current.Parent, depth++)
        {
            var attachedOwners = (current.GetCustomProperty(BurnCheckPropertyName) as BurnAttachment)?.Owners;
            if (attachedOwners is not null)
            {
                foreach (var owner in attachedOwners)
                {
                    owners = MergeOwners(owners, owner);
                }
            }

            if (current.GetCustomProperty(PropagationPolicyPropertyName) is PropagationPolicy policy)
            {
                hasAnyPolicy = true;
                if (policy.IsRejected)
                {
                    isRejected = true;
                }
                if (!policy.AllowRawPayloads)
                {
                    allPoliciesAllowRaw = false;
                }
                allowlist ??= policy.Allowlist;
            }
        }

        if (current is not null)
        {
            // Fail closed if ancestor walk exceeds depth guard (e.g., cyclic Activity parenting).
            isRejected = true;
            allPoliciesAllowRaw = false;
        }

        return new PropagationHierarchyState(owners, isRejected, hasAnyPolicy, allPoliciesAllowRaw, allowlist);
    }

    private sealed class ExporterDispatchLease(Activity? activity, Func<bool>? externalBurnCheck, object[]? owners)
    {
        private readonly object _sync = new();
        private bool _completed;

        public object[]? Owners { get; } = owners;
        public bool HasOwners => Owners is { Length: > 0 };
        public bool MatchesOwner(object serviceOwner) => HasOwner(Owners, serviceOwner);

        public bool IsCompleted
        {
            get
            {
                lock (_sync)
                {
                    return _completed;
                }
            }
        }

        public bool SafeCheckBurned()
        {
            var checking = _checkingBurnLeases ??= new HashSet<ExporterDispatchLease>(ReferenceEqualityComparer.Instance);
            if (!checking.Add(this))
            {
                // Avoid infinite recursion if a caller-supplied isBurned callback invokes service.Burn() reentrantly.
                return false;
            }
            try
            {
                return activity is not null
                    ? IsActivityBurned(activity, externalBurnCheck)
                    : IsPredicateBurnedSafe(externalBurnCheck);
            }
            finally
            {
                checking.Remove(this);
            }
        }

        public void Complete()
        {
            lock (_sync)
            {
                _completed = true;
                Monitor.PulseAll(_sync);
            }
        }

        public void Wait()
        {
            lock (_sync)
            {
                while (!_completed)
                {
                    Monitor.Wait(_sync);
                }
            }
        }
    }

    private sealed class AncestorLeaseNode(ExporterDispatchLease lease, AncestorLeaseNode? next)
    {
        public ExporterDispatchLease Lease { get; } = lease;
        public AncestorLeaseNode? Next { get; } = next;

        public bool Contains(ExporterDispatchLease target)
        {
            for (var current = this; current is not null; current = current.Next)
            {
                if (ReferenceEquals(current.Lease, target))
                {
                    return true;
                }
            }
            return false;
        }
    }

    internal sealed class PurgeWaitNode(Task task, object owner, PurgeWaitNode? next)
    {
        public Task Task { get; } = task;
        public object Owner { get; } = owner;
        public PurgeWaitNode? Next { get; } = next;

        public bool ContainsTask(Task candidate)
        {
            for (var current = this; current is not null; current = current.Next)
            {
                if (ReferenceEquals(current.Task, candidate))
                {
                    return true;
                }
            }
            return false;
        }

        public bool ContainsOwner(object candidate)
        {
            for (var current = this; current is not null; current = current.Next)
            {
                if (ReferenceEquals(current.Owner, candidate))
                {
                    return true;
                }
            }
            return false;
        }
    }

    internal static PurgeWaitNode? CurrentPurgeScope
    {
        get => t_currentPurgeHolders;
        set => t_currentPurgeHolders = value;
    }

    internal static List<object> CaptureCurrentWaitHolders(object? additionalHolder = null)
    {
        var holders = new List<object>();
        for (var current = t_currentAncestorDispatches; current is not null; current = current.Next)
        {
            holders.Add(current.Lease);
        }
        for (var current = t_currentPurgeHolders; current is not null; current = current.Next)
        {
            holders.Add(current.Task);
        }
        if (additionalHolder is not null)
        {
            var alreadyPresent = false;
            foreach (var holder in holders)
            {
                if (ReferenceEquals(holder, additionalHolder))
                {
                    alreadyPresent = true;
                    break;
                }
            }
            if (!alreadyPresent)
            {
                holders.Add(additionalHolder);
            }
        }
        return holders;
    }

    private static bool WouldCreateWaitCycleLocked(object startTarget, HashSet<object> holderSet)
    {
        if (holderSet.Contains(startTarget))
        {
            return true;
        }
        if (!WaitEdges.TryGetValue(startTarget, out var initialNext) || initialNext.Count == 0)
        {
            return false;
        }

        var visited = new HashSet<object>(ReferenceEqualityComparer.Instance) { startTarget };
        var stack = new Stack<object>(initialNext.Keys);
        while (stack.Count > 0)
        {
            var current = stack.Pop();
            if (holderSet.Contains(current))
            {
                return true;
            }
            if (!visited.Add(current))
            {
                continue;
            }
            if (WaitEdges.TryGetValue(current, out var nextTargets))
            {
                foreach (var next in nextTargets.Keys)
                {
                    if (!visited.Contains(next))
                    {
                        stack.Push(next);
                    }
                }
            }
        }

        return false;
    }

    private static void RegisterWaitEdgesLocked(List<object> holders, object waitTarget)
    {
        foreach (var holder in holders)
        {
            if (!WaitEdges.TryGetValue(holder, out var targets))
            {
                targets = new Dictionary<object, int>(ReferenceEqualityComparer.Instance);
                WaitEdges[holder] = targets;
            }
            targets[waitTarget] = targets.GetValueOrDefault(waitTarget) + 1;
        }
    }

    private static void UnregisterWaitEdgeLocked(object holder, object waitTarget)
    {
        if (!WaitEdges.TryGetValue(holder, out var targets) ||
            !targets.TryGetValue(waitTarget, out var count))
        {
            return;
        }
        if (count <= 1)
        {
            targets.Remove(waitTarget);
        }
        else
        {
            targets[waitTarget] = count - 1;
        }
        if (targets.Count == 0)
        {
            WaitEdges.Remove(holder);
        }
    }

    private static bool TryBeginWaitLocked(object waitTarget, List<object> holders, HashSet<object>? holderSet)
    {
        if (holderSet is not null && WouldCreateWaitCycleLocked(waitTarget, holderSet))
        {
            return false;
        }
        if (holders.Count > 0)
        {
            RegisterWaitEdgesLocked(holders, waitTarget);
        }
        return true;
    }

    internal static List<Task>? SelectNonCyclicPriorPurges(
        IReadOnlyList<Task> activeTasks,
        PurgeWaitNode? ancestorPurges,
        List<object> holders)
    {
        List<Task>? priorPurges = null;
        var holderSet = holders.Count > 0
            ? new HashSet<object>(holders, ReferenceEqualityComparer.Instance)
            : null;
        lock (WaitGraphSync)
        {
            foreach (var activeTask in activeTasks)
            {
                if (ancestorPurges is not null && ancestorPurges.ContainsTask(activeTask))
                {
                    continue;
                }
                if (!TryBeginWaitLocked(activeTask, holders, holderSet))
                {
                    continue;
                }
                priorPurges ??= new List<Task>();
                priorPurges.Add(activeTask);
            }
        }
        return priorPurges;
    }

    internal static void EndWait(List<object>? holders, object waitTarget)
    {
        if (holders is null || holders.Count == 0)
        {
            return;
        }
        lock (WaitGraphSync)
        {
            foreach (var holder in holders)
            {
                UnregisterWaitEdgeLocked(holder, waitTarget);
            }
        }
    }

    internal static void EndWaitMany(List<object>? holders, List<Task>? waitTargets)
    {
        if (holders is null || holders.Count == 0 || waitTargets is null || waitTargets.Count == 0)
        {
            return;
        }
        lock (WaitGraphSync)
        {
            foreach (var holder in holders)
            {
                foreach (var waitTarget in waitTargets)
                {
                    UnregisterWaitEdgeLocked(holder, waitTarget);
                }
            }
        }
    }

    internal static void RegisterOwnerPurgeAction(object owner, Action<object> purgeAction)
    {
        ArgumentNullException.ThrowIfNull(owner);
        ArgumentNullException.ThrowIfNull(purgeAction);

        lock (ActiveDispatchSync)
        {
            var actions = OwnerPurgeActions.GetValue(owner, static _ => new List<Action<object>>());
            if (!actions.Contains(purgeAction))
            {
                actions.Add(purgeAction);
            }
        }
    }

    private static List<(object Owner, Action<object>[] Actions)>? CollectBurnedOwnerPurgesLocked(object[]? leaseOwners)
    {
        if (leaseOwners is null || leaseOwners.Length == 0)
        {
            return null;
        }

        List<(object Owner, Action<object>[] Actions)>? purges = null;
        foreach (var owner in leaseOwners)
        {
            if (BurnedOwners.TryGetValue(owner, out _) &&
                OwnerPurgeActions.TryGetValue(owner, out var actions) &&
                actions.Count > 0)
            {
                purges ??= new List<(object Owner, Action<object>[] Actions)>();
                purges.Add((owner, actions.ToArray()));
            }
        }
        return purges;
    }

    internal static void BurnServiceAndWait(object serviceOwner, object burnSync, Action markBurned)
    {
        var ancestors = t_currentAncestorDispatches;
        Dictionary<ExporterDispatchLease, bool>? unownedBefore = null;

        // Evaluate caller-controlled burn predicates outside burnSync and ActiveDispatchSync so an
        // external isBurned callback that invokes service.Burn() cannot deadlock with BurnServiceAndWait.
        for (var attempt = 0; attempt < 4; attempt++)
        {
            List<ExporterDispatchLease>? needCheck = null;
            lock (ActiveDispatchSync)
            {
                foreach (var lease in ActiveDispatches)
                {
                    if (ancestors is not null && ancestors.Contains(lease))
                    {
                        continue;
                    }
                    if (!lease.HasOwners && (unownedBefore is null || !unownedBefore.ContainsKey(lease)))
                    {
                        needCheck ??= new List<ExporterDispatchLease>();
                        needCheck.Add(lease);
                    }
                }
            }
            if (needCheck is null)
            {
                break;
            }
            unownedBefore ??= new Dictionary<ExporterDispatchLease, bool>(ReferenceEqualityComparer.Instance);
            foreach (var lease in needCheck)
            {
                unownedBefore[lease] = lease.SafeCheckBurned();
            }
        }

        List<ExporterDispatchLease>? toWait = null;
        List<ExporterDispatchLease>? unownedToCheckAfter = null;
        var serviceAlreadyBurned = false;
        lock (burnSync)
        {
            lock (ActiveDispatchSync)
            {
                serviceAlreadyBurned = BurnedOwners.TryGetValue(serviceOwner, out _);
                BurnedOwners.AddOrUpdate(serviceOwner, BurnedOwnerSentinel);
                markBurned();
                foreach (var lease in ActiveDispatches)
                {
                    if (ancestors is not null && ancestors.Contains(lease))
                    {
                        continue;
                    }
                    if (lease.HasOwners)
                    {
                        if (lease.MatchesOwner(serviceOwner))
                        {
                            toWait ??= new List<ExporterDispatchLease>();
                            toWait.Add(lease);
                        }
                    }
                    else
                    {
                        unownedToCheckAfter ??= new List<ExporterDispatchLease>();
                        unownedToCheckAfter.Add(lease);
                    }
                }
            }
        }

        if (unownedToCheckAfter is not null)
        {
            foreach (var lease in unownedToCheckAfter)
            {
                if (lease.IsCompleted)
                {
                    continue;
                }
                if (lease.HasOwners)
                {
                    if (lease.MatchesOwner(serviceOwner))
                    {
                        toWait ??= new List<ExporterDispatchLease>();
                        toWait.Add(lease);
                    }
                    continue;
                }
                if (!serviceAlreadyBurned &&
                    unownedBefore is not null &&
                    unownedBefore.TryGetValue(lease, out var wasBurnedBefore) &&
                    wasBurnedBefore)
                {
                    continue;
                }
                // Wait conservatively when an unowned predicate is now true without mutating lease.Owner,
                // so concurrent burns on another service cannot steal ownership and cause the true owner's
                // Burn() to return before this callback finishes.
                if (lease.SafeCheckBurned())
                {
                    toWait ??= new List<ExporterDispatchLease>();
                    toWait.Add(lease);
                }
            }
        }

        if (toWait is null || toWait.Count == 0)
        {
            ScrubOwnedActivities(serviceOwner);
            return;
        }

        var holders = CaptureCurrentWaitHolders();
        var holderSet = holders.Count > 0
            ? new HashSet<object>(holders, ReferenceEqualityComparer.Instance)
            : null;
        foreach (var target in toWait)
        {
            var canWait = false;
            lock (ActiveDispatchSync)
            {
                lock (WaitGraphSync)
                {
                    if (!target.IsCompleted && TryBeginWaitLocked(target, holders, holderSet))
                    {
                        canWait = true;
                    }
                }
            }

            if (!canWait)
            {
                continue;
            }

            try
            {
                target.Wait();
            }
            finally
            {
                EndWait(holders, target);
            }
        }

        ScrubOwnedActivities(serviceOwner);
    }

    private static void ScrubOwnedActivities(object serviceOwner)
    {
        List<Activity>? activities = null;
        lock (ActiveDispatchSync)
        {
            if (OwnedActivities.TryGetValue(serviceOwner, out var table))
            {
                foreach (var kv in table)
                {
                    activities ??= new List<Activity>();
                    activities.Add(kv.Key);
                }
                table.Clear();
            }
        }
        if (activities is null)
        {
            return;
        }
        foreach (var act in activities)
        {
            try
            {
                MarkBurnedAndScrub(act);
            }
            catch
            {
                // Best-effort scrub of concurrently mutated Activity instances.
            }
        }
    }

    private sealed class ActivityPublicationScope(ExporterDispatchLease lease, AncestorLeaseNode? previousAncestors)
        : IDisposable
    {
        public void Dispose()
        {
            t_currentAncestorDispatches = previousAncestors;
            lock (ActiveDispatchSync)
            {
                ActiveDispatches.Remove(lease);
            }
            lease.Complete();
        }
    }

    internal static bool TryBeginActivityPublication(
        Activity? activity,
        object serviceOwner,
        Func<bool> isBurned,
        out IDisposable? scope)
    {
        ExporterDispatchLease? lease = null;
        lock (ActiveDispatchSync)
        {
            if (!BurnedOwners.TryGetValue(serviceOwner, out _) && !isBurned())
            {
                lease = new ExporterDispatchLease(activity, isBurned, new[] { serviceOwner });
                ActiveDispatches.Add(lease);
            }
        }

        if (lease is null)
        {
            scope = null;
            return false;
        }

        var previousAncestors = t_currentAncestorDispatches;
        t_currentAncestorDispatches = new AncestorLeaseNode(lease, previousAncestors);
        scope = new ActivityPublicationScope(lease, previousAncestors);
        return true;
    }

    internal static void EndActivityPublication(IDisposable? scope)
    {
        scope?.Dispose();
    }

    internal static void AttachBurnCheck(Activity activity, Func<bool> isBurned, object? owner = null)
    {
        object[]? mergedOwners;
        Func<bool>[] mergedChecks;
        switch (activity.GetCustomProperty(BurnCheckPropertyName))
        {
            case BurnAttachment existing:
                mergedOwners = MergeOwners(existing.Owners, owner);
                mergedChecks = MergeChecks(existing.Checks, isBurned);
                break;
            case Func<bool> existingCheck:
                mergedOwners = MergeOwners(null, owner);
                mergedChecks = MergeChecks(new[] { existingCheck }, isBurned);
                break;
            default:
                mergedOwners = MergeOwners(null, owner);
                mergedChecks = MergeChecks(null, isBurned);
                break;
        }

        activity.SetCustomProperty(BurnCheckPropertyName, new BurnAttachment(mergedChecks, mergedOwners));
        RegisterActivityWithOwners(activity, ResolveHierarchyOwners(activity));
    }

    private static void RegisterActivityWithOwners(Activity activity, object[]? owners)
    {
        if (owners is null || owners.Length == 0)
        {
            return;
        }

        var anyAlreadyBurned = false;
        lock (ActiveDispatchSync)
        {
            foreach (var owner in owners)
            {
                if (BurnedOwners.TryGetValue(owner, out _))
                {
                    anyAlreadyBurned = true;
                }
                else
                {
                    var table = OwnedActivities.GetOrCreateValue(owner);
                    table.AddOrUpdate(activity, BurnedOwnerSentinel);
                }
            }
        }

        if (anyAlreadyBurned)
        {
            MarkBurnedAndScrub(activity);
        }
    }

    internal static void MarkBurnedAndScrub(Activity activity)
    {
        activity.ActivityTraceFlags &= ~ActivityTraceFlags.Recorded;
        activity.IsAllDataRequested = false;
        var existingOwners = ResolveHierarchyOwners(activity);
        activity.SetCustomProperty(BurnCheckPropertyName, new BurnAttachment(AlwaysBurnedChecks, existingOwners));
        var existingAllowlist = (activity.GetCustomProperty(PropagationPolicyPropertyName) as PropagationPolicy)?.Allowlist
            ?? DefaultFailClosedAllowlist;
        activity.SetCustomProperty(
            PropagationPolicyPropertyName,
            new PropagationPolicy(existingAllowlist, allowRawPayloads: false, isRejected: true));
        ScrubFailedActivity(activity);
    }

    internal static bool IsActivityBurned(Activity activity, Func<bool>? externalBurnCheck = null)
    {
        try
        {
            if (IsPredicateBurnedSafe(externalBurnCheck))
            {
                return true;
            }
            var depth = 0;
            var current = activity;
            for (; current is not null && depth < 64; current = current.Parent, depth++)
            {
                var isCurrentBurned = current.GetCustomProperty(BurnCheckPropertyName) switch
                {
                    BurnAttachment attachment => attachment.IsBurned(),
                    Func<bool> check => check(),
                    _ => false,
                };
                if (isCurrentBurned)
                {
                    return true;
                }
            }
            // Fail closed if ancestor walk exceeds depth guard.
            return current is not null;
        }
        catch
        {
            // Fail closed if reading burn state throws (e.g., disposed session state).
            return true;
        }
    }

    private static bool IsSafeScalarTagValue(object? value) =>
        value is string or bool or float or double or decimal
            or byte or sbyte or short or ushort or int or uint or long or ulong;

    /// <summary>
    /// Sanitizes all tags currently attached to an Activity in place, throwing <see cref="InvalidOperationException"/>
    /// fail-closed if immutable metadata or direct unsanitized events/links violate the allowlist.
    /// For export-pipeline processors and listener stop callbacks that enqueue or serialize spans, wrap the entire
    /// downstream enqueue/export step with
    /// <see cref="CreateExporterSafeStopCallback(SafeAllowlist, Action{Activity}, PrivacyTelemetryService, bool, Action?)"/>
    /// so publication-lease coordination and post-burn queue purging cover the whole export operation.
    /// </summary>
    public static Activity SanitizeActivity(Activity activity, SafeAllowlist allowlist, bool allowRawPayloads = false)
    {
        ArgumentNullException.ThrowIfNull(activity);
        ArgumentNullException.ThrowIfNull(allowlist);

        const int maxSanitizePasses = 4;
        var hasNullTagKey = false;
        var stabilized = false;
        var detachedRuleIds = new HashSet<string[]>(ReferenceEqualityComparer.Instance);

        for (var pass = 0; pass < maxSanitizePasses; pass++)
        {
            hasNullTagKey = false;
            var groupedByKey = new Dictionary<string, List<object?>>(StringComparer.Ordinal);
            foreach (var tag in activity.TagObjects)
            {
                if (tag.Key is null)
                {
                    hasNullTagKey = true;
                    continue;
                }
                if (!groupedByKey.TryGetValue(tag.Key, out var values))
                {
                    values = new List<object?>();
                    groupedByKey[tag.Key] = values;
                }
                values.Add(tag.Value);
            }

            var mutatedThisPass = false;
            foreach (var (key, values) in groupedByKey)
            {
                if (!allowRawPayloads &&
                    (!allowlist.IsAllowed(key) || SafeAllowlist.IsCollectorBoundaryExcludedKey(key)))
                {
                    RemoveTagsByKey(activity, key);
                    mutatedThisPass = true;
                    continue;
                }

                var targetKey = key.Length > SafeAllowlist.MaxStringLength
                    ? SafeAllowlist.FormatTruncatedDigest(key)
                    : key;
                var keyWasTruncated = !string.Equals(targetKey, key, StringComparison.Ordinal);

                object? sanitizedFinal = null;
                var isRuleIdsKey = targetKey.Equals("rule_ids", StringComparison.OrdinalIgnoreCase);
                var allAlreadyClean =
                    !keyWasTruncated &&
                    values.Count == 1 &&
                    (IsSafeScalarTagValue(values[0]) ||
                     (isRuleIdsKey && values[0] is string[] existingRuleIds && detachedRuleIds.Contains(existingRuleIds)));

                foreach (var rawVal in values)
                {
                    var sanitized = allowlist.SanitizeValue(key, rawVal!, allowRawPayloads);
                    var isUnchangedCleanValue =
                        (IsSafeScalarTagValue(rawVal) && Equals(sanitized, rawVal)) ||
                        (isRuleIdsKey &&
                         rawVal is string[] rawRuleIds &&
                         detachedRuleIds.Contains(rawRuleIds) &&
                         sanitized is string[] sanitizedRuleIds &&
                         rawRuleIds.AsSpan().SequenceEqual(sanitizedRuleIds));
                    if (!isUnchangedCleanValue)
                    {
                        allAlreadyClean = false;
                    }
                    if (sanitized is string s &&
                        (s == SafeAllowlist.RedactedNotAllowlisted || s == SafeAllowlist.RedactedSensitiveValue))
                    {
                        sanitizedFinal = s;
                        if (s == SafeAllowlist.RedactedSensitiveValue)
                        {
                            break;
                        }
                    }
                    else
                    {
                        sanitizedFinal = sanitized;
                    }
                }

                if (allAlreadyClean)
                {
                    continue;
                }

                if (isRuleIdsKey && sanitizedFinal is string[] detachedSanitizedRuleIds)
                {
                    detachedRuleIds.Add(detachedSanitizedRuleIds);
                }

                RemoveTagsByKey(activity, key);
                if (keyWasTruncated)
                {
                    RemoveTagsByKey(activity, targetKey);
                }
                activity.SetTag(targetKey, sanitizedFinal);
                mutatedThisPass = true;
            }

            if (!mutatedThisPass)
            {
                stabilized = true;
                break;
            }
        }

        if (!stabilized)
        {
            throw new InvalidOperationException("Activity tags did not stabilize during sanitization.");
        }

        // Fail closed at export boundary if caller attached unsanitized ActivityEvent or ActivityLink
        // tags directly (ActivityEvent.Tags and ActivityLink.Tags are immutable in System.Diagnostics),
        // or if immutable metadata exceeds safe length limits (including when allowRawPayloads is true).
        if (hasNullTagKey)
        {
            throw new InvalidOperationException("Activity contains a null tag key that cannot be safely removed.");
        }

        if (!allowRawPayloads)
        {
            if (!string.IsNullOrEmpty(activity.DisplayName) &&
                activity.DisplayName != "[REDACTED_SPAN_NAME]" &&
                !SafeAllowlist.IsSafeEventName(activity.DisplayName))
            {
                activity.DisplayName = "[REDACTED_SPAN_NAME]";
            }

            if (!string.IsNullOrEmpty(activity.StatusDescription))
            {
                activity.SetStatus(activity.Status, null);
            }

            // Assign string.Empty unconditionally (even when null) so ambient parent TraceStateString cannot inherit on Start().
            activity.TraceStateString = string.Empty;

            SanitizeActivityBaggage(activity, allowlist);

            var rejectionReason = FindUnsafeImmutableTagReason(activity, allowlist);
            if (rejectionReason is not null)
            {
                throw new InvalidOperationException(rejectionReason);
            }
        }
        else
        {
            TruncateOversizedActivityBaggage(activity);
        }

        if (!string.IsNullOrEmpty(activity.DisplayName) &&
            activity.DisplayName.Length > SafeAllowlist.MaxStringLength)
        {
            activity.DisplayName = SafeAllowlist.FormatTruncatedDigest(activity.DisplayName);
        }

        if (!string.IsNullOrEmpty(activity.StatusDescription) &&
            activity.StatusDescription.Length > SafeAllowlist.MaxStringLength)
        {
            activity.SetStatus(activity.Status, SafeAllowlist.FormatTruncatedDigest(activity.StatusDescription));
        }

        if (!string.IsNullOrEmpty(activity.TraceStateString) &&
            activity.TraceStateString.Length > SafeAllowlist.MaxStringLength)
        {
            activity.TraceStateString = SafeAllowlist.FormatTruncatedDigest(activity.TraceStateString);
        }

        var oversizedReason = FindOversizedImmutableMetadataReason(activity);
        if (oversizedReason is not null)
        {
            throw new InvalidOperationException(oversizedReason);
        }

        return activity;
    }

    /// <summary>
    /// Performs point-in-time sanitization of mutable <see cref="Activity.TagObjects"/> and checks immutable events/links
    /// without throwing into <see cref="Activity.Stop"/> or listener callbacks. When unsafe
    /// immutable tags are present, clears recording flags so downstream exporters drop the span.
    /// Note: Because <see cref="TrySanitizeActivity"/> returns before any caller-side enqueue or serialization step,
    /// processors and stop callbacks that enqueue or export spans must wrap that downstream operation with
    /// <see cref="CreateExporterSafeStopCallback(SafeAllowlist, Action{Activity}, PrivacyTelemetryService, bool, Action?)"/>
    /// so the publication lease and post-burn queue purge cover the entire enqueue/serialization window.
    /// </summary>
    public static bool TrySanitizeActivity(
        Activity activity,
        SafeAllowlist allowlist,
        out string? rejectionReason,
        bool allowRawPayloads = false) =>
        TrySanitizeActivityCore(activity, allowlist, out rejectionReason, allowRawPayloads, isBurned: null);

    private static bool TrySanitizeActivityCore(
        Activity activity,
        SafeAllowlist allowlist,
        out string? rejectionReason,
        bool allowRawPayloads,
        Func<bool>? isBurned)
    {
        ArgumentNullException.ThrowIfNull(activity);
        ArgumentNullException.ThrowIfNull(allowlist);

        var initialOwners = ResolveHierarchyOwners(activity);
        RegisterActivityWithOwners(activity, initialOwners);
        ExporterDispatchLease? lease = null;
        var ownerBurned = false;
        lock (ActiveDispatchSync)
        {
            if (IsAnyOwnerBurnedLocked(initialOwners))
            {
                ownerBurned = true;
            }
            else if (initialOwners is { Length: > 0 } || isBurned is not null)
            {
                lease = new ExporterDispatchLease(activity, isBurned, initialOwners);
                ActiveDispatches.Add(lease);
            }
        }

        if (ownerBurned)
        {
            MarkBurnedAndScrub(activity);
            rejectionReason = "Telemetry service has been burned.";
            return false;
        }

        var previousAncestors = t_currentAncestorDispatches;
        if (lease is not null)
        {
            t_currentAncestorDispatches = new AncestorLeaseNode(lease, previousAncestors);
        }

        try
        {
            activity.SetCustomProperty(
                PropagationPolicyPropertyName,
                new PropagationPolicy(allowlist, allowRawPayloads, isRejected: false));

            try
            {
                if (IsActivityBurned(activity, isBurned))
                {
                    MarkBurnedAndScrub(activity);
                    rejectionReason = "Telemetry service has been burned.";
                    return false;
                }

                SanitizeActivity(activity, allowlist, allowRawPayloads);

                // Recheck after sanitization in case a lazy tag enumerable triggered Burn().
                if (IsActivityBurned(activity, isBurned))
                {
                    MarkBurnedAndScrub(activity);
                    rejectionReason = "Telemetry service has been burned.";
                    return false;
                }

                var attachedOwners = ResolveHierarchyOwners(activity);
                RegisterActivityWithOwners(activity, attachedOwners);
                if (HasDisallowedExternalPublicationOwner(attachedOwners))
                {
                    activity.ActivityTraceFlags &= ~ActivityTraceFlags.Recorded;
                    activity.IsAllDataRequested = false;
                    activity.SetCustomProperty(
                        PropagationPolicyPropertyName,
                        new PropagationPolicy(allowlist, allowRawPayloads: false, isRejected: true));
                    rejectionReason = "Attached Telemetry service forbids external Activity publication.";
                    return false;
                }

                rejectionReason = null;
                return true;
            }
            catch (Exception ex)
            {
                activity.ActivityTraceFlags &= ~ActivityTraceFlags.Recorded;
                activity.IsAllDataRequested = false;
                activity.SetCustomProperty(
                    PropagationPolicyPropertyName,
                    new PropagationPolicy(allowlist, allowRawPayloads: false, isRejected: true));
                ScrubFailedActivity(activity);
                rejectionReason = ex.Message;
                return false;
            }
        }
        finally
        {
            if (lease is not null)
            {
                t_currentAncestorDispatches = previousAncestors;
                lock (ActiveDispatchSync)
                {
                    ActiveDispatches.Remove(lease);
                }
                lease.Complete();
            }
        }
    }

    private static void ScrubFailedActivity(Activity activity)
    {
        try
        {
            var keys = new HashSet<string>(StringComparer.Ordinal);
            foreach (var tag in activity.TagObjects)
            {
                if (tag.Key is not null)
                {
                    keys.Add(tag.Key);
                }
            }
            foreach (var key in keys)
            {
                RemoveTagsByKey(activity, key);
            }
            if (!string.IsNullOrEmpty(activity.DisplayName))
            {
                activity.DisplayName = "[REDACTED_SPAN_NAME]";
            }
            if (!string.IsNullOrEmpty(activity.StatusDescription))
            {
                activity.SetStatus(activity.Status, null);
            }
            activity.TraceStateString = string.Empty;
            ClearActivityBaggage(activity);
        }
        catch
        {
            // Never allow cleanup failures to escape ActivityListener / Stop callbacks.
        }
    }

    private static void ClearActivityBaggage(Activity activity)
    {
        var baggageKeys = new HashSet<string>(StringComparer.Ordinal);
        foreach (var item in activity.Baggage)
        {
            if (item.Key is not null)
            {
                baggageKeys.Add(item.Key);
            }
        }
        foreach (var key in baggageKeys)
        {
            RemoveAllLocalBaggageByKey(activity, key);
        }
    }

    private static int CountBaggageOccurrences(Activity activity, string key)
    {
        var count = 0;
        foreach (var item in activity.Baggage)
        {
            if (string.Equals(item.Key, key, StringComparison.Ordinal))
            {
                count++;
            }
        }
        return count;
    }

    private static void RemoveAllLocalBaggageByKey(Activity activity, string key)
    {
        // Note: In .NET, Activity.Baggage enumerates both local and inherited ancestor entries,
        // while Activity.SetBaggage(key, null) removes only entries attached locally on `activity`.
        // When an ancestor Activity carries non-allowlisted or unsanitized baggage, this loop stops
        // once local entries are cleared and FindUnsafeImmutableTagReason intentionally rejects the
        // child span fail-closed (whereas PrivacyTelemetryService.RecordSpan starts spans from a
        // detached ActivityContext so service-recorded spans never inherit ambient parent baggage).
        var currentCount = CountBaggageOccurrences(activity, key);
        while (currentCount > 0)
        {
            activity.SetBaggage(key, null);
            var nextCount = CountBaggageOccurrences(activity, key);
            if (nextCount >= currentCount)
            {
                break;
            }
            currentCount = nextCount;
        }
    }

    private static void SanitizeActivityBaggage(Activity activity, SafeAllowlist allowlist) =>
        RewriteActivityBaggage(
            activity,
            includeKey: _ => true,
            resolveEntry: (key, vals) =>
            {
                if (!allowlist.IsAllowed(key) || SafeAllowlist.IsCollectorBoundaryExcludedKey(key))
                {
                    return (Apply: true, Value: null);
                }

                if (vals.Count == 1 &&
                    vals[0] is string singleRaw &&
                    Equals(allowlist.SanitizeValue(key, singleRaw, allowRawPayloads: false), singleRaw))
                {
                    return (Apply: false, Value: null);
                }

                var resolved = SafeAllowlist.RedactedSensitiveValue;
                foreach (var rawVal in vals)
                {
                    var sanitized = allowlist.SanitizeValue(key, rawVal ?? string.Empty, allowRawPayloads: false);
                    var sanitizedStr = sanitized as string ?? sanitized?.ToString() ?? SafeAllowlist.RedactedSensitiveValue;
                    resolved = sanitizedStr;
                    if (sanitizedStr == SafeAllowlist.RedactedSensitiveValue)
                    {
                        break;
                    }
                }

                return (Apply: true, Value: resolved);
            });

    private static void TruncateOversizedActivityBaggage(Activity activity) =>
        RewriteActivityBaggage(
            activity,
            includeKey: key => key.Length <= SafeAllowlist.MaxStringLength,
            resolveEntry: (_, vals) =>
            {
                var hasOversized = false;
                string? replacement = null;
                foreach (var val in vals)
                {
                    if (val is not null && val.Length > SafeAllowlist.MaxStringLength)
                    {
                        hasOversized = true;
                        replacement = SafeAllowlist.FormatTruncatedDigest(val);
                    }
                    else if (!hasOversized)
                    {
                        replacement = val;
                    }
                }

                return hasOversized ? (Apply: true, Value: replacement) : (Apply: false, Value: null);
            });

    private static void RewriteActivityBaggage(
        Activity activity,
        Func<string, bool> includeKey,
        Func<string, List<string?>, (bool Apply, string? Value)> resolveEntry)
    {
        const int maxBaggagePasses = 4;
        for (var pass = 0; pass < maxBaggagePasses; pass++)
        {
            var mutated = false;
            var grouped = new Dictionary<string, List<string?>>(StringComparer.Ordinal);
            foreach (var item in activity.Baggage)
            {
                if (item.Key is null || !includeKey(item.Key))
                {
                    continue;
                }
                if (!grouped.TryGetValue(item.Key, out var vals))
                {
                    vals = new List<string?>();
                    grouped[item.Key] = vals;
                }
                vals.Add(item.Value);
            }

            if (grouped.Count == 0)
            {
                return;
            }

            foreach (var (key, vals) in grouped)
            {
                var (apply, value) = resolveEntry(key, vals);
                if (apply)
                {
                    RemoveAllLocalBaggageByKey(activity, key);
                    if (value is not null)
                    {
                        activity.SetBaggage(key, value);
                    }
                    mutated = true;
                }
            }

            if (!mutated)
            {
                break;
            }
        }
    }

    private static string? FindOversizedImmutableMetadataReason(Activity activity)
    {
        if (!string.IsNullOrEmpty(activity.Id) &&
            activity.Id.Length > SafeAllowlist.MaxStringLength)
        {
            return "Activity ID exceeds maximum safe metadata length.";
        }
        if (!string.IsNullOrEmpty(activity.ParentId) &&
            activity.ParentId.Length > SafeAllowlist.MaxStringLength)
        {
            return "Activity parent ID exceeds maximum safe metadata length.";
        }
        if (activity.Source.Name.Length > SafeAllowlist.MaxStringLength)
        {
            return "Activity source name exceeds maximum safe metadata length.";
        }
        if (!string.IsNullOrEmpty(activity.Source.Version) &&
            activity.Source.Version.Length > SafeAllowlist.MaxStringLength)
        {
            return "Activity source version exceeds maximum safe metadata length.";
        }
        if (!string.IsNullOrEmpty(activity.Source.TelemetrySchemaUrl) &&
            activity.Source.TelemetrySchemaUrl.Length > SafeAllowlist.MaxStringLength)
        {
            return "Activity source telemetry schema URL exceeds maximum safe metadata length.";
        }
        if (activity.Source.Tags is { } sourceTags && HasOversizedTag(sourceTags))
        {
            return "Activity source tag exceeds maximum safe metadata length.";
        }

        foreach (var evt in activity.Events)
        {
            if (evt.Name.Length > SafeAllowlist.MaxStringLength)
            {
                return "Activity event name exceeds maximum safe metadata length.";
            }

            if (HasOversizedTag(evt.Tags))
            {
                return "Activity event tag exceeds maximum safe metadata length.";
            }
        }

        foreach (var link in activity.Links)
        {
            if (!string.IsNullOrEmpty(link.Context.TraceState) &&
                link.Context.TraceState.Length > SafeAllowlist.MaxStringLength)
            {
                return "Activity link trace state exceeds maximum safe metadata length.";
            }

            if (link.Tags is not null && HasOversizedTag(link.Tags))
            {
                return "Activity link tag exceeds maximum safe metadata length.";
            }
        }

        if (!string.IsNullOrEmpty(activity.OperationName) &&
            activity.OperationName.Length > SafeAllowlist.MaxStringLength)
        {
            return "Activity operation name exceeds maximum safe metadata length.";
        }

        foreach (var baggage in activity.Baggage)
        {
            if (baggage.Key is null ||
                baggage.Key.Length > SafeAllowlist.MaxStringLength ||
                (baggage.Value is not null && baggage.Value.Length > SafeAllowlist.MaxStringLength))
            {
                return "Activity baggage exceeds maximum safe metadata length.";
            }
        }

        return null;
    }

    private static bool HasOversizedTag(IEnumerable<KeyValuePair<string, object?>> tags)
    {
        foreach (var tag in tags)
        {
            if (tag.Key is null ||
                tag.Key.Length > SafeAllowlist.MaxStringLength ||
                IsOversizedTagValue(tag.Key, tag.Value))
            {
                return true;
            }
        }
        return false;
    }

    private static bool IsOversizedTagValue(string key, object? value)
    {
        switch (value)
        {
            case null:
            case bool:
            case sbyte or byte or short or ushort or int or uint or long or ulong or float or double or decimal:
                return false;
            case string s:
                var maxLen = key.Equals("rule_ids", StringComparison.OrdinalIgnoreCase)
                    ? SafeAllowlist.MaxRuleIdsCsvLength
                    : SafeAllowlist.MaxStringLength;
                return s.Length > maxLen;
            case System.Collections.IEnumerable seq:
                var count = 0;
                foreach (var item in seq)
                {
                    count++;
                    if (count > SafeAllowlist.MaxRuleIds)
                    {
                        return true;
                    }
                    switch (item)
                    {
                        case null:
                        case bool:
                        case sbyte or byte or short or ushort or int or uint or long or ulong or float or double or decimal:
                            break;
                        case string strItem:
                            if (strItem.Length > SafeAllowlist.MaxStringLength)
                            {
                                return true;
                            }
                            break;
                        default:
                            if (item is System.Collections.IEnumerable ||
                                item.ToString() is { Length: > SafeAllowlist.MaxStringLength })
                            {
                                return true;
                            }
                            break;
                    }
                }
                return false;
            default:
                return value.ToString() is { Length: > SafeAllowlist.MaxStringLength };
        }
    }

    private static string? FindUnsafeImmutableTagReason(Activity activity, SafeAllowlist allowlist)
    {
        if (!allowlist.IsSafeActivitySource(activity.Source.Name))
        {
            return "Activity source name violates privacy naming policy. Use a registered namespace without free text or sensitive patterns.";
        }
        if (!string.IsNullOrEmpty(activity.Source.Version) &&
            !SafeAllowlist.IsSafeAppVersion(activity.Source.Version))
        {
            return "Activity source version violates safe version policy.";
        }
        if (!string.IsNullOrEmpty(activity.Source.TelemetrySchemaUrl))
        {
            return "Activity source contains unsafe telemetry schema URL. Remove TelemetrySchemaUrl before exporting telemetry.";
        }
        if (activity.Source.Tags is { } sourceTags)
        {
            using var enumerator = sourceTags.GetEnumerator();
            if (enumerator.MoveNext())
            {
                return "Activity source contains unsafe immutable scope tags. Remove ActivitySource tags before exporting telemetry.";
            }
        }

        foreach (var evt in activity.Events)
        {
            if (evt.Name != SafeAllowlist.RedactedSensitiveValue &&
                !SafeAllowlist.IsSafeEventName(evt.Name))
            {
                return "Activity event has unsanitized event name. Use PrivacyActivityEnricher.AddSanitizedEvent.";
            }

            var reason = FindUnsafeTagReason(
                evt.Tags,
                allowlist,
                "Activity event",
                "Use PrivacyActivityEnricher.AddSanitizedEvent.");
            if (reason is not null)
            {
                return reason;
            }
        }

        foreach (var link in activity.Links)
        {
            if (!string.IsNullOrEmpty(link.Context.TraceState))
            {
                return "Activity link contains unsafe immutable trace state. Clear TraceState before creating ActivityLink.";
            }

            if (link.Tags is null)
            {
                continue;
            }

            var reason = FindUnsafeTagReason(
                link.Tags,
                allowlist,
                "Activity link",
                "Sanitize link tags with SafeAllowlist before creating ActivityLink.");
            if (reason is not null)
            {
                return reason;
            }
        }

        if (!string.IsNullOrEmpty(activity.OperationName) &&
            activity.OperationName != "[REDACTED_SPAN_NAME]" &&
            !SafeAllowlist.IsSafeEventName(activity.OperationName))
        {
            return "Activity operation name is immutable and unregistered. Start activities with a registered span name or SafeAllowlist.SanitizeSpanName.";
        }

        if (!string.IsNullOrEmpty(activity.ParentId) &&
            !StrictTraceParentRegex.IsMatch(activity.ParentId))
        {
            return "Activity parent ID violates W3C trace context format. Use W3C ActivityContext or valid W3C traceparent IDs.";
        }

        if ((activity.IdFormat != ActivityIdFormat.Unknown && activity.IdFormat != ActivityIdFormat.W3C) ||
            (!string.IsNullOrEmpty(activity.Id) && !StrictTraceParentRegex.IsMatch(activity.Id)))
        {
            return "Activity ID violates W3C trace context format. Use ActivityIdFormat.W3C for exported activities.";
        }

        foreach (var baggage in activity.Baggage)
        {
            if (string.IsNullOrEmpty(baggage.Key) ||
                !allowlist.IsAllowed(baggage.Key) ||
                SafeAllowlist.IsCollectorBoundaryExcludedKey(baggage.Key))
            {
                return "Activity contains unsafe baggage. Remove non-allowlisted Activity.Baggage entries before exporting telemetry.";
            }

            var rawValue = baggage.Value ?? string.Empty;
            var sanitizedValue = allowlist.SanitizeValue(baggage.Key, rawValue, allowRawPayloads: false);
            var sanitizedString = sanitizedValue as string ?? sanitizedValue?.ToString();
            if (!string.Equals(sanitizedString, baggage.Value, StringComparison.Ordinal))
            {
                return "Activity contains unsanitized baggage value. Sanitize or clear Activity.Baggage before exporting telemetry.";
            }
        }

        return null;
    }

    private static string? FindUnsafeTagReason(
        IEnumerable<KeyValuePair<string, object?>> tags,
        SafeAllowlist allowlist,
        string containerLabel,
        string remediationHint)
    {
        foreach (var tag in tags)
        {
            if (tag.Key is null)
            {
                return $"{containerLabel} contains a null tag key; {remediationHint}";
            }

            if (!allowlist.IsAllowed(tag.Key) || SafeAllowlist.IsCollectorBoundaryExcludedKey(tag.Key))
            {
                return $"{containerLabel} contains unallowlisted tag. {remediationHint}";
            }

            if (tag.Value is System.Collections.IEnumerable and not string)
            {
                // Immutable ActivityEvent/ActivityLink tags cannot swap mutable arrays or lazy enumerables
                // after validation; accept only a detached ImmutableArray<string> checked via one snapshot copy.
                if (tag.Value is not System.Collections.Immutable.ImmutableArray<string> immutableValue)
                {
                    return $"{containerLabel} contains non-snapshot enumerable tag. {remediationHint}";
                }

                var snapshot = immutableValue.IsDefault ? Array.Empty<string>() : immutableValue.ToArray();
                var sanitizedSnapshot = allowlist.SanitizeValue(tag.Key, snapshot, allowRawPayloads: false);
                if (!AreSanitizedTagValuesEqual(sanitizedSnapshot, snapshot))
                {
                    return $"{containerLabel} contains unsanitized tag. {remediationHint}";
                }
                continue;
            }

            var sanitized = allowlist.SanitizeValue(tag.Key, tag.Value!, allowRawPayloads: false);
            if (!AreSanitizedTagValuesEqual(sanitized, tag.Value))
            {
                return $"{containerLabel} contains unsanitized tag. {remediationHint}";
            }
        }

        return null;
    }

    private static bool AreSanitizedTagValuesEqual(object? sanitized, object? original)
    {
        if (Equals(sanitized, original))
        {
            return true;
        }

        if (sanitized is string[] sanitizedArray &&
            original is string[] originalArray)
        {
            return sanitizedArray.AsSpan().SequenceEqual(originalArray.AsSpan());
        }

        return false;
    }

    /// <summary>
    /// Creates an <see cref="ActivityEvent"/> whose tags are strictly scrubbed through the supplied allowlist
    /// prior to immutable construction.
    /// </summary>
    public static ActivityEvent CreateSanitizedEvent(
        string name,
        SafeAllowlist allowlist,
        IEnumerable<KeyValuePair<string, object?>>? tags = null,
        bool allowRawPayloads = false,
        DateTimeOffset timestamp = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        ArgumentNullException.ThrowIfNull(allowlist);

        var safeName = allowRawPayloads
            ? SafeAllowlist.SanitizeSpanName(name, allowRawPayloads: true)
            : (name == SafeAllowlist.RedactedSensitiveValue || SafeAllowlist.IsSafeEventName(name)
                ? name
                : SafeAllowlist.RedactedSensitiveValue);

        if (tags is null)
        {
            return new ActivityEvent(safeName, timestamp);
        }

        var cleanTags = new ActivityTagsCollection();
        foreach (var tag in tags)
        {
            if (tag.Key is null)
            {
                continue;
            }
            if (!allowRawPayloads &&
                (!allowlist.IsAllowed(tag.Key) || SafeAllowlist.IsCollectorBoundaryExcludedKey(tag.Key)))
            {
                continue;
            }
            var sanitizedValue = allowlist.SanitizeValue(tag.Key, tag.Value!, allowRawPayloads);
            var targetKey = tag.Key.Length > SafeAllowlist.MaxStringLength
                ? SafeAllowlist.FormatTruncatedDigest(tag.Key)
                : tag.Key;
            cleanTags[targetKey] = sanitizedValue is string[] sanitizedStrings
                ? System.Collections.Immutable.ImmutableArray.Create(sanitizedStrings)
                : sanitizedValue;
        }

        return new ActivityEvent(safeName, timestamp, cleanTags);
    }

    /// <summary>
    /// Sanitizes event tags against <paramref name="allowlist"/> and appends the event to <paramref name="activity"/>.
    /// </summary>
    public static Activity AddSanitizedEvent(
        Activity activity,
        string name,
        SafeAllowlist allowlist,
        IEnumerable<KeyValuePair<string, object?>>? tags = null,
        bool allowRawPayloads = false,
        DateTimeOffset timestamp = default)
    {
        ArgumentNullException.ThrowIfNull(activity);
        ArgumentNullException.ThrowIfNull(allowlist);
        ExecuteSanitizedActivityMutation(activity, () =>
        {
            var sanitizedEvent = CreateSanitizedEvent(name, allowlist, tags, allowRawPayloads, timestamp);
            if (IsActivityOrOwnerBurned(activity))
            {
                MarkBurnedAndScrub(activity);
                return;
            }
            activity.AddEvent(sanitizedEvent);
        });
        return activity;
    }

    private static void RemoveTagsByKey(Activity activity, string key)
    {
        while (activity.TagObjects.Any(t => string.Equals(t.Key, key, StringComparison.Ordinal)))
        {
            activity.SetTag(key, null);
        }
    }

    /// <summary>
    /// Attaches a tag after fail-closed allowlist sanitization so sensitive inputs never enter Activity state.
    /// </summary>
    public static Activity SetSanitizedTag(
        this Activity activity,
        string key,
        object? value,
        SafeAllowlist allowlist,
        bool allowRawPayloads = false)
    {
        ArgumentNullException.ThrowIfNull(activity);
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(allowlist);

        ExecuteSanitizedActivityMutation(activity, () =>
        {
            if (!allowRawPayloads &&
                (!allowlist.IsAllowed(key) || SafeAllowlist.IsCollectorBoundaryExcludedKey(key)))
            {
                RemoveTagsByKey(activity, key);
                return;
            }

            var sanitizedValue = allowlist.SanitizeValue(key, value!, allowRawPayloads);
            if (IsActivityOrOwnerBurned(activity))
            {
                MarkBurnedAndScrub(activity);
                return;
            }

            var targetKey = key.Length > SafeAllowlist.MaxStringLength
                ? SafeAllowlist.FormatTruncatedDigest(key)
                : key;
            RemoveTagsByKey(activity, key);
            if (!string.Equals(targetKey, key, StringComparison.Ordinal))
            {
                RemoveTagsByKey(activity, targetKey);
            }
            activity.SetTag(targetKey, sanitizedValue);
        });
        return activity;
    }

    private static bool IsActivityOrOwnerBurned(Activity activity)
    {
        var owners = ResolveHierarchyOwners(activity);
        bool anyOwnerBurned;
        lock (ActiveDispatchSync)
        {
            anyOwnerBurned = IsAnyOwnerBurnedLocked(owners);
        }

        return anyOwnerBurned || IsActivityBurned(activity);
    }

    private static void ExecuteSanitizedActivityMutation(Activity activity, Action mutate)
    {
        if (IsActivityOrOwnerBurned(activity))
        {
            MarkBurnedAndScrub(activity);
            return;
        }

        ExporterDispatchLease? lease = null;
        var ownerBurned = false;
        var attachedOwners = ResolveHierarchyOwners(activity);
        RegisterActivityWithOwners(activity, attachedOwners);
        lock (ActiveDispatchSync)
        {
            if (IsAnyOwnerBurnedLocked(attachedOwners))
            {
                ownerBurned = true;
            }
            else
            {
                lease = new ExporterDispatchLease(activity, () => IsActivityBurned(activity), attachedOwners);
                ActiveDispatches.Add(lease);
            }
        }

        if (ownerBurned || lease is null)
        {
            MarkBurnedAndScrub(activity);
            return;
        }

        var previousAncestors = t_currentAncestorDispatches;
        t_currentAncestorDispatches = new AncestorLeaseNode(lease, previousAncestors);
        try
        {
            if (IsActivityOrOwnerBurned(activity))
            {
                MarkBurnedAndScrub(activity);
                return;
            }

            mutate();

            if (IsActivityOrOwnerBurned(activity))
            {
                MarkBurnedAndScrub(activity);
            }
        }
        finally
        {
            t_currentAncestorDispatches = previousAncestors;
            lock (ActiveDispatchSync)
            {
                ActiveDispatches.Remove(lease);
            }
            lease.Complete();
        }
    }

    /// <summary>
    /// Wraps an exporter stop callback so Activity tags are sanitized before exporter serialization
    /// regardless of ActivityListener registration order.
    /// When used with <see cref="PrivacyTelemetryService"/>, either pass the service to
    /// <see cref="CreateExporterSafeStopCallback(SafeAllowlist, Action{Activity}, PrivacyTelemetryService, bool, Action?)"/>
    /// or bind spans at creation via <see cref="CreateSanitizingListener(SafeAllowlist, PrivacyTelemetryService, Func{ActivitySource, bool}?, bool)"/>
    /// so service egress and burn policies govern every exported Activity.
    /// </summary>
    public static Action<Activity> CreateExporterSafeStopCallback(
        SafeAllowlist allowlist,
        Action<Activity> exporterOnStop,
        bool allowRawPayloads = false) =>
        CreateExporterSafeStopCallback(allowlist, exporterOnStop, allowRawPayloads, isBurned: null);

    /// <summary>
    /// Wraps an exporter stop callback bound to a <see cref="PrivacyTelemetryService"/> instance so
    /// burn checks and concurrent burn-drain coordination apply even to external <see cref="ActivitySource"/>s.
    /// Contract: <paramref name="exporterOnStop"/> executes synchronously on the caller thread so an
    /// external <c>Burn()</c> can drain in-flight exports; asynchronous/batched exporters must register a
    /// purge callback via the <c>onBurnPurge</c> overload or <see cref="PrivacyTelemetryService.RegisterBurnPurgeHook"/>.
    /// Callbacks must not block synchronously on a detached <c>Burn()</c> task (for example via
    /// <c>Task.Run(service.Burn).Wait()</c>).
    /// </summary>
    public static Action<Activity> CreateExporterSafeStopCallback(
        SafeAllowlist allowlist,
        Action<Activity> exporterOnStop,
        PrivacyTelemetryService service,
        bool allowRawPayloads = false) =>
        CreateExporterSafeStopCallback(allowlist, exporterOnStop, service, allowRawPayloads, onBurnPurge: null);

    /// <summary>
    /// Wraps an exporter stop callback bound to a <see cref="PrivacyTelemetryService"/> instance and
    /// registers an optional <paramref name="onBurnPurge"/> delegate invoked synchronously by
    /// <see cref="PrivacyTelemetryService.Burn"/> after active stop callbacks drain, purging any queued
    /// records before <c>Burn()</c> returns.
    /// </summary>
    public static Action<Activity> CreateExporterSafeStopCallback(
        SafeAllowlist allowlist,
        Action<Activity> exporterOnStop,
        PrivacyTelemetryService service,
        bool allowRawPayloads,
        Action? onBurnPurge)
    {
        ArgumentNullException.ThrowIfNull(service);
        if (onBurnPurge is not null)
        {
            service.RegisterBurnPurgeHook(onBurnPurge);
        }
        return CreateExporterSafeStopCallbackCore(
            allowlist,
            exporterOnStop,
            allowRawPayloads,
            () => service.IsBurned,
            explicitOwner: service);
    }

    /// <summary>
    /// Wraps an exporter stop callback so Activity tags are sanitized and service burn state is checked
    /// before exporter serialization regardless of ActivityListener registration order.
    /// Contract: <paramref name="exporterOnStop"/> executes synchronously on the caller thread so an
    /// external <c>Burn()</c> can drain in-flight exports; callbacks must not block synchronously on a
    /// detached <c>Burn()</c> task (for example via <c>Task.Run(service.Burn).Wait()</c>).
    /// </summary>
    public static Action<Activity> CreateExporterSafeStopCallback(
        SafeAllowlist allowlist,
        Action<Activity> exporterOnStop,
        bool allowRawPayloads,
        Func<bool>? isBurned) =>
        CreateExporterSafeStopCallbackCore(allowlist, exporterOnStop, allowRawPayloads, isBurned, explicitOwner: null);

    private static Action<Activity> CreateExporterSafeStopCallbackCore(
        SafeAllowlist allowlist,
        Action<Activity> exporterOnStop,
        bool allowRawPayloads,
        Func<bool>? isBurned,
        object? explicitOwner)
    {
        ArgumentNullException.ThrowIfNull(allowlist);
        ArgumentNullException.ThrowIfNull(exporterOnStop);

        return activity =>
        {
            var effectiveBurnCheck = isBurned;
            var existingOwners = ResolveHierarchyOwners(activity);
            var directOwners = (activity.GetCustomProperty(BurnCheckPropertyName) as BurnAttachment)?.Owners;
            if (directOwners is { Length: > 0 } &&
                explicitOwner is not null &&
                !HasOwner(directOwners, explicitOwner))
            {
                // Preserve per-service isolation when a shared ActivitySource dispatches ActivityStopped
                // to another service's exporter listener: sanitize under the owning service's policy
                // without attaching the unrelated service as an owner or suppressing the owner's export.
                SanitizeListenerActivity(activity, allowlist, allowRawPayloads, isBurned: null, owner: null);
                return;
            }
            if (explicitOwner is not null &&
                (existingOwners is null or { Length: 0 } || HasOwner(existingOwners, explicitOwner)))
            {
                AttachBurnCheck(
                    activity,
                    isBurned ?? (explicitOwner is PrivacyTelemetryService svc ? () => svc.IsBurned : static () => false),
                    explicitOwner);
                effectiveBurnCheck = null;
            }
            else if (explicitOwner is not null)
            {
                effectiveBurnCheck = null;
            }

            if (!TrySanitizeActivityCore(activity, allowlist, out _, allowRawPayloads, effectiveBurnCheck))
            {
                return;
            }

            ExporterDispatchLease? lease = null;
            var hierarchyState = ResolvePropagationHierarchyState(activity);
            var attachedOwners = hierarchyState.Owners;
            var leaseOwners = MergeOwners(attachedOwners, explicitOwner);
            RegisterActivityWithOwners(activity, leaseOwners);
            var anyOwnerBurned = false;
            lock (ActiveDispatchSync)
            {
                anyOwnerBurned = IsAnyOwnerBurnedLocked(leaseOwners);
                // Note: AddPrivacyTelemetry registers zero OpenTelemetry exporters in consumer builds,
                // and PrivacyTelemetryService.RecordSpan creates Activities only when AllowsExternalActivityPublication
                // is true (mode == "otlp", non-empty OtlpEndpoint, and networkEgress in allow_otlp/allow_all).
                // When any PrivacyTelemetryService owns the Activity (via CreateSanitizingListener, RecordSpan, or
                // the service-bound CreateExporterSafeStopCallback overload), HasDisallowedExternalPublicationOwner
                // enforces that service's mode/endpoint/egress policy fail-closed; ownerless callbacks are reserved
                // for standalone SafeAllowlist + Func<bool>? isBurned pipelines where no PrivacyTelemetryService exists.
                if (!anyOwnerBurned &&
                    !hierarchyState.IsRejected &&
                    !HasDisallowedExternalPublicationOwner(leaseOwners))
                {
                    lease = new ExporterDispatchLease(activity, effectiveBurnCheck, leaseOwners);
                    ActiveDispatches.Add(lease);
                }
            }

            if (anyOwnerBurned)
            {
                MarkBurnedAndScrub(activity);
                return;
            }

            if (lease is null)
            {
                return;
            }

            var previousAncestors = t_currentAncestorDispatches;
            t_currentAncestorDispatches = new AncestorLeaseNode(lease, previousAncestors);
            try
            {
                // Check caller-controlled burn state outside ActiveDispatchSync and burnSync so an
                // isBurned predicate invoking service.Burn() cannot invert lock ordering or self-deadlock.
                if (IsActivityBurned(activity, effectiveBurnCheck))
                {
                    MarkBurnedAndScrub(activity);
                    return;
                }

                exporterOnStop(activity);
            }
            finally
            {
                List<(object Owner, Action<object>[] Actions)>? burnedOwnerPurges;
                lock (ActiveDispatchSync)
                {
                    burnedOwnerPurges = CollectBurnedOwnerPurgesLocked(leaseOwners);
                }

                try
                {
                    if (burnedOwnerPurges is not null)
                    {
                        foreach (var (owner, actions) in burnedOwnerPurges)
                        {
                            foreach (var action in actions)
                            {
                                try
                                {
                                    action(owner);
                                }
                                catch
                                {
                                    // Swallow purge hook exceptions inside ActivityStopped so hook failures
                                    // never escape Activity.Stop()/Dispose() into unrelated caller code;
                                    // explicit Burn() calls run RunPurgeHooksCore and surface hook exceptions.
                                }
                            }
                        }
                    }
                }
                finally
                {
                    t_currentAncestorDispatches = previousAncestors;
                    lock (ActiveDispatchSync)
                    {
                        ActiveDispatches.Remove(lease);
                    }
                    lease.Complete();
                }
            }
        };
    }

    /// <summary>
    /// Creates an in-process <see cref="ActivityListener"/> that sanitizes spans started on KnowThankYew sources.
    /// Registration order contract: <see cref="System.Diagnostics.ActivitySource"/> invokes listeners in
    /// registration order, so register this listener at startup before any exporter listener, and enforce
    /// <see cref="TrySanitizeActivity"/> (dropping export when it returns <see langword="false"/>) in
    /// export-pipeline processors (e.g., <c>BaseProcessor&lt;Activity&gt;.OnEnd</c>) or wrap exporter callbacks
    /// with <see cref="CreateExporterSafeStopCallback(SafeAllowlist, Action{Activity}, bool)"/> so downstream exporters never observe unsanitized tags.
    /// </summary>
    public static ActivityListener CreateSanitizingListener(
        SafeAllowlist allowlist,
        bool allowRawPayloads = false) =>
        CreateSanitizingListener(allowlist, allowRawPayloads, shouldListenTo: null, isBurned: null);

    /// <summary>
    /// Creates an in-process <see cref="ActivityListener"/> that sanitizes spans for a specific source filter.
    /// </summary>
    public static ActivityListener CreateSanitizingListener(
        SafeAllowlist allowlist,
        Func<ActivitySource, bool> shouldListenTo,
        bool allowRawPayloads = false) =>
        CreateSanitizingListener(allowlist, allowRawPayloads, shouldListenTo, isBurned: null);

    /// <summary>
    /// Creates an in-process <see cref="ActivityListener"/> bound to a <see cref="PrivacyTelemetryService"/>
    /// instance so spans started on external sources inherit burn enforcement and owner attribution.
    /// </summary>
    public static ActivityListener CreateSanitizingListener(
        SafeAllowlist allowlist,
        PrivacyTelemetryService service,
        Func<ActivitySource, bool>? shouldListenTo = null,
        bool allowRawPayloads = false)
    {
        ArgumentNullException.ThrowIfNull(service);
        return CreateSanitizingListenerCore(allowlist, allowRawPayloads, shouldListenTo, () => service.IsBurned, owner: service);
    }

    /// <summary>
    /// Creates an in-process <see cref="ActivityListener"/> that sanitizes spans and enforces burn suppression.
    /// </summary>
    public static ActivityListener CreateSanitizingListener(
        SafeAllowlist allowlist,
        bool allowRawPayloads,
        Func<ActivitySource, bool>? shouldListenTo,
        Func<bool>? isBurned) =>
        CreateSanitizingListenerCore(allowlist, allowRawPayloads, shouldListenTo, isBurned, owner: null);

    /// <summary>
    /// Creates a fail-closed <see cref="DistributedContextPropagator"/> that strips non-allowlisted or
    /// unsanitized baggage (including baggage inherited from an ambient parent <see cref="Activity"/>),
    /// removes <c>tracestate</c>, and suppresses all propagation for rejected or burned activities
    /// unless <paramref name="allowRawPayloads"/> is explicitly enabled (and the activity is not burned).
    /// </summary>
    public static DistributedContextPropagator CreateSanitizingPropagator(
        SafeAllowlist allowlist,
        bool allowRawPayloads = false,
        Func<bool>? isBurned = null,
        DistributedContextPropagator? innerPropagator = null)
    {
        ArgumentNullException.ThrowIfNull(allowlist);
        var inner = UnwrapPropagator(innerPropagator ?? DistributedContextPropagator.Current);
        return new PrivacySafeDistributedContextPropagator(inner, allowlist, allowRawPayloads, isBurned, isExplicit: true, explicitOwner: null);
    }

    /// <summary>
    /// Creates a fail-closed <see cref="DistributedContextPropagator"/> bound to a
    /// <see cref="PrivacyTelemetryService"/> instance.
    /// </summary>
    public static DistributedContextPropagator CreateSanitizingPropagator(
        SafeAllowlist allowlist,
        PrivacyTelemetryService service,
        bool allowRawPayloads = false,
        DistributedContextPropagator? innerPropagator = null)
    {
        ArgumentNullException.ThrowIfNull(allowlist);
        ArgumentNullException.ThrowIfNull(service);
        var inner = UnwrapPropagator(innerPropagator ?? DistributedContextPropagator.Current);
        return new PrivacySafeDistributedContextPropagator(inner, allowlist, allowRawPayloads, () => service.IsBurned, isExplicit: true, explicitOwner: service);
    }

    /// <summary>
    /// Explicitly installs a process-wide <see cref="DistributedContextPropagator.Current"/> wrapper
    /// that enforces allowlist baggage sanitization and service burn/egress policies on outbound context injection.
    /// Because <see cref="DistributedContextPropagator.Current"/> is process-global, call this only when opting in
    /// at application startup (or via <c>IServiceProvider.UsePrivacySafePropagator()</c>).
    /// </summary>
    public static DistributedContextPropagator InstallSanitizingPropagator(
        SafeAllowlist allowlist,
        PrivacyTelemetryService? service = null,
        bool? allowRawPayloads = null,
        DistributedContextPropagator? innerPropagator = null)
    {
        ArgumentNullException.ThrowIfNull(allowlist);
        lock (PropagatorSync)
        {
            var current = innerPropagator ?? DistributedContextPropagator.Current;
            var installed = new PrivacySafeDistributedContextPropagator(
                UnwrapPropagator(current),
                allowlist: allowlist,
                allowRawPayloads: allowRawPayloads ?? service?.AllowRawPayloads ?? false,
                isBurned: service is not null ? () => service.IsBurned : null,
                isExplicit: false,
                explicitOwner: service);
            DistributedContextPropagator.Current = installed;
            return installed;
        }
    }

    private static DistributedContextPropagator UnwrapPropagator(DistributedContextPropagator? candidate)
    {
        var current = candidate;
        while (current is PrivacySafeDistributedContextPropagator wrapper)
        {
            current = wrapper.Inner;
        }
        return current ?? DistributedContextPropagator.CreateDefaultPropagator();
    }

    private static ActivityListener CreateSanitizingListenerCore(
        SafeAllowlist allowlist,
        bool allowRawPayloads,
        Func<ActivitySource, bool>? shouldListenTo,
        Func<bool>? isBurned,
        object? owner)
    {
        ArgumentNullException.ThrowIfNull(allowlist);

        var listener = new ActivityListener
        {
            ShouldListenTo = shouldListenTo ?? (source => source.Name.StartsWith("KnowThankYew", StringComparison.Ordinal)),
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllData,
            SampleUsingParentId = (ref ActivityCreationOptions<string> _) => ActivitySamplingResult.AllData,
            ActivityStarted = activity => SanitizeListenerActivity(activity, allowlist, allowRawPayloads, isBurned, owner),
            ActivityStopped = activity => SanitizeListenerActivity(activity, allowlist, allowRawPayloads, isBurned, owner)
        };

        return listener;
    }

    private static void SanitizeListenerActivity(
        Activity activity,
        SafeAllowlist allowlist,
        bool allowRawPayloads,
        Func<bool>? isBurned,
        object? owner)
    {
        var effectiveAllowlist = allowlist;
        var effectiveAllowRawPayloads = allowRawPayloads;
        var effectiveBurnCheck = isBurned;
        var existingOwners = ResolveHierarchyOwners(activity);
        if (existingOwners is { Length: > 0 } && (owner is null || !HasOwner(existingOwners, owner)))
        {
            // Preserve per-service isolation when a shared source emits spans owned by a different service instance.
            effectiveBurnCheck = null;
            if (activity.GetCustomProperty(PropagationPolicyPropertyName) is PropagationPolicy existingPolicy)
            {
                effectiveAllowlist = existingPolicy.Allowlist;
                effectiveAllowRawPayloads = existingPolicy.AllowRawPayloads && !existingPolicy.IsRejected;
            }
            else if (ResolvePropagationHierarchyState(activity) is { HasAnyPolicy: true, Allowlist: { } inheritedAllowlist } hierarchyState)
            {
                effectiveAllowlist = inheritedAllowlist;
                effectiveAllowRawPayloads = hierarchyState.AllPoliciesAllowRaw && !hierarchyState.IsRejected;
            }
            else if (existingOwners[0] is PrivacyTelemetryService owningService)
            {
                effectiveAllowlist = owningService.Allowlist;
                effectiveAllowRawPayloads = owningService.AllowRawPayloads;
            }
        }
        else if (isBurned is not null || owner is not null)
        {
            AttachBurnCheck(
                activity,
                isBurned ?? (owner is PrivacyTelemetryService svc ? () => svc.IsBurned : static () => false),
                owner);
        }

        TrySanitizeActivityCore(activity, effectiveAllowlist, out _, effectiveAllowRawPayloads, effectiveBurnCheck);
    }

    private static bool IsAnyOwnerBurnedOrDisallowed(object[]? owners)
    {
        if (owners is null || owners.Length == 0)
        {
            return false;
        }
        lock (ActiveDispatchSync)
        {
            return IsAnyOwnerBurnedLocked(owners) || HasDisallowedExternalPublicationOwner(owners);
        }
    }

    private sealed class PrivacySafeDistributedContextPropagator : DistributedContextPropagator
    {
        internal DistributedContextPropagator Inner { get; }
        internal object? ExplicitOwner => _explicitOwner;
        private readonly SafeAllowlist? _allowlist;
        private readonly bool _allowRawPayloads;
        private readonly Func<bool>? _isBurned;
        private readonly bool _isExplicit;
        private readonly object? _explicitOwner;

        public PrivacySafeDistributedContextPropagator(
            DistributedContextPropagator inner,
            SafeAllowlist? allowlist,
            bool allowRawPayloads,
            Func<bool>? isBurned,
            bool isExplicit,
            object? explicitOwner)
        {
            Inner = inner;
            _allowlist = allowlist;
            _allowRawPayloads = allowRawPayloads;
            _isBurned = isBurned;
            _isExplicit = isExplicit;
            _explicitOwner = explicitOwner;
        }

        public override IReadOnlyCollection<string> Fields => Inner.Fields;

        public override void ExtractTraceIdAndState(
            object? carrier,
            PropagatorGetterCallback? getter,
            out string? traceId,
            out string? traceState) =>
            Inner.ExtractTraceIdAndState(carrier, getter, out traceId, out traceState);

        public override IEnumerable<KeyValuePair<string, string?>>? ExtractBaggage(
            object? carrier,
            PropagatorGetterCallback? getter) =>
            Inner.ExtractBaggage(carrier, getter);

        public override void Inject(Activity? activity, object? carrier, PropagatorSetterCallback? setter)
        {
            if (setter is null)
            {
                return;
            }

            var effectiveActivity = activity ?? Activity.Current;
            var hierarchy = ResolvePropagationHierarchyState(effectiveActivity);
            var attachedOwners = hierarchy.Owners;
            var leaseOwners = _isExplicit
                ? (_explicitOwner is not null ? CombineOwnerObjects(attachedOwners, _explicitOwner) : attachedOwners)
                : (attachedOwners is { Length: > 0 }
                    ? attachedOwners
                    : (_explicitOwner is not null ? new[] { _explicitOwner } : null));
            var effectiveBurnPredicate = _isExplicit || attachedOwners is null or { Length: 0 }
                ? _isBurned
                : null;

            if (IsPredicateBurnedSafe(effectiveBurnPredicate) ||
                (effectiveActivity is not null && IsActivityBurned(effectiveActivity, effectiveBurnPredicate)))
            {
                if (effectiveActivity is not null)
                {
                    MarkBurnedAndScrub(effectiveActivity);
                }
                return;
            }

            var isRejected = hierarchy.IsRejected;
            var attachedAllowsRaw = hierarchy.HasAnyPolicy
                ? hierarchy.AllPoliciesAllowRaw
                : _allowRawPayloads;
            var allowRaw = _isExplicit
                ? (_allowRawPayloads && !isRejected)
                : (attachedAllowsRaw && !isRejected);

            if (isRejected && !allowRaw)
            {
                return;
            }

            ExporterDispatchLease? lease = null;
            var blocked = false;
            lock (ActiveDispatchSync)
            {
                if (IsAnyOwnerBurnedLocked(leaseOwners) ||
                    HasDisallowedExternalPublicationOwner(leaseOwners) ||
                    (!_isExplicit && leaseOwners is { Length: > 0 } && !HasAllowedExternalPublicationOwner(leaseOwners)))
                {
                    blocked = true;
                }
                else
                {
                    lease = new ExporterDispatchLease(effectiveActivity, effectiveBurnPredicate, leaseOwners);
                    ActiveDispatches.Add(lease);
                }
            }

            if (blocked || lease is null)
            {
                if (effectiveActivity is not null && IsActivityBurned(effectiveActivity, effectiveBurnPredicate))
                {
                    MarkBurnedAndScrub(effectiveActivity);
                }
                return;
            }

            var previousAncestors = t_currentAncestorDispatches;
            t_currentAncestorDispatches = new AncestorLeaseNode(lease, previousAncestors);
            try
            {
                if (IsPredicateBurnedSafe(effectiveBurnPredicate) ||
                    (effectiveActivity is not null && IsActivityBurned(effectiveActivity, effectiveBurnPredicate)) ||
                    IsAnyOwnerBurnedOrDisallowed(leaseOwners))
                {
                    if (effectiveActivity is not null && IsActivityBurned(effectiveActivity, effectiveBurnPredicate))
                    {
                        MarkBurnedAndScrub(effectiveActivity);
                    }
                    return;
                }

                var hasAnySafeBaggage = false;
                string? safeBaggageHeader = null;
                if (!allowRaw && effectiveActivity is not null)
                {
                    var effectiveAllowlist = _isExplicit
                        ? (_allowlist ?? hierarchy.Allowlist ?? DefaultFailClosedAllowlist)
                        : (hierarchy.Allowlist ?? _allowlist ?? DefaultFailClosedAllowlist);
                    const int maxBaggageEntries = 64;
                    const int maxBaggageEncodedLength = 8192;
                    var currentEncodedLength = 0;
                    List<string>? sanitizedPairs = null;

                    foreach (var baggage in effectiveActivity.Baggage)
                    {
                        if (string.IsNullOrEmpty(baggage.Key) ||
                            baggage.Key.Length > SafeAllowlist.MaxStringLength ||
                            !effectiveAllowlist.IsAllowed(baggage.Key) ||
                            SafeAllowlist.IsCollectorBoundaryExcludedKey(baggage.Key))
                        {
                            continue;
                        }

                        var rawValue = baggage.Value ?? string.Empty;
                        var sanitized = effectiveAllowlist.SanitizeValue(baggage.Key, rawValue, allowRawPayloads: false);
                        var sanitizedStr = sanitized as string ?? sanitized?.ToString() ?? SafeAllowlist.RedactedSensitiveValue;
                        if (sanitizedStr.Length > SafeAllowlist.MaxStringLength)
                        {
                            sanitizedStr = SafeAllowlist.FormatTruncatedDigest(sanitizedStr);
                        }

                        var pair = $"{Uri.EscapeDataString(baggage.Key)}={Uri.EscapeDataString(sanitizedStr)}";
                        var separatorLength = sanitizedPairs is { Count: > 0 } ? 2 : 0;
                        if ((sanitizedPairs?.Count ?? 0) >= maxBaggageEntries ||
                            currentEncodedLength + separatorLength + pair.Length > maxBaggageEncodedLength)
                        {
                            break;
                        }

                        sanitizedPairs ??= new List<string>();
                        sanitizedPairs.Add(pair);
                        currentEncodedLength += separatorLength + pair.Length;
                    }

                    hasAnySafeBaggage = sanitizedPairs is { Count: > 0 };
                    safeBaggageHeader = hasAnySafeBaggage
                        ? string.Join(", ", sanitizedPairs!)
                        : null;
                }

                Inner.Inject(activity, carrier, (c, fieldName, fieldValue) =>
                {
                    if (IsPredicateBurnedSafe(effectiveBurnPredicate) ||
                        (effectiveActivity is not null && IsActivityBurned(effectiveActivity, effectiveBurnPredicate)) ||
                        IsAnyOwnerBurnedOrDisallowed(leaseOwners))
                    {
                        return;
                    }

                    if (allowRaw)
                    {
                        setter(c, fieldName, fieldValue);
                        return;
                    }

                    if (string.Equals(fieldName, "traceparent", StringComparison.OrdinalIgnoreCase))
                    {
                        if (!string.IsNullOrEmpty(fieldValue) && StrictTraceParentRegex.IsMatch(fieldValue))
                        {
                            setter(c, fieldName, fieldValue);
                        }
                        return;
                    }

                    if (string.Equals(fieldName, "baggage", StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(fieldName, "Correlation-Context", StringComparison.OrdinalIgnoreCase))
                    {
                        if (effectiveActivity is not null && safeBaggageHeader is not null)
                        {
                            setter(c, fieldName, safeBaggageHeader);
                        }
                        return;
                    }
                });

                if (effectiveActivity is not null && IsActivityBurned(effectiveActivity, effectiveBurnPredicate))
                {
                    MarkBurnedAndScrub(effectiveActivity);
                }
            }
            finally
            {
                t_currentAncestorDispatches = previousAncestors;
                lock (ActiveDispatchSync)
                {
                    ActiveDispatches.Remove(lease);
                }
                lease.Complete();
            }
        }
    }
}
