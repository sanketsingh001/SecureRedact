namespace FintechGuard.Pii.Ner;

internal readonly record struct AhoCorasickMatch(int PatternIndex, int Start, int Length);

/// <summary>
/// Multi-pattern case-insensitive Aho-Corasick automaton running in strictly O(n) time
/// with zero regex overhead and net8.0 + net10.0 compatibility.
/// </summary>
internal sealed class AhoCorasickMatcher
{
    private sealed class Node
    {
        public Dictionary<char, int>? Transitions;
        public int Failure;
        public List<int>? Outputs;
    }

    private readonly List<Node> _nodes = new() { new Node() };
    private readonly int[] _patternLengths;

    public AhoCorasickMatcher(IReadOnlyList<string> patterns)
    {
        _patternLengths = new int[patterns.Count];
        for (int i = 0; i < patterns.Count; i++)
        {
            string p = patterns[i];
            _patternLengths[i] = p.Length;
            if (p.Length == 0) continue;

            int state = 0;
            for (int cIdx = 0; cIdx < p.Length; cIdx++)
            {
                char ch = char.ToLowerInvariant(p[cIdx]);
                var node = _nodes[state];
                node.Transitions ??= new Dictionary<char, int>(4);
                if (!node.Transitions.TryGetValue(ch, out int next))
                {
                    next = _nodes.Count;
                    _nodes.Add(new Node());
                    node.Transitions[ch] = next;
                }
                state = next;
            }

            var endNode = _nodes[state];
            endNode.Outputs ??= new List<int>(1);
            endNode.Outputs.Add(i);
        }

        BuildFailureLinks();
    }

    private void BuildFailureLinks()
    {
        var queue = new Queue<int>();
        var root = _nodes[0];
        if (root.Transitions == null) return;

        foreach (int child in root.Transitions.Values)
        {
            _nodes[child].Failure = 0;
            queue.Enqueue(child);
        }

        while (queue.Count > 0)
        {
            int state = queue.Dequeue();
            var node = _nodes[state];
            if (node.Transitions == null) continue;

            foreach (var kvp in node.Transitions)
            {
                char ch = kvp.Key;
                int nextState = kvp.Value;

                int fail = node.Failure;
                while (fail != 0 && (_nodes[fail].Transitions == null || !_nodes[fail].Transitions!.ContainsKey(ch)))
                {
                    fail = _nodes[fail].Failure;
                }

                if (_nodes[fail].Transitions != null && _nodes[fail].Transitions!.TryGetValue(ch, out int failTarget) && failTarget != nextState)
                {
                    _nodes[nextState].Failure = failTarget;
                }
                else
                {
                    _nodes[nextState].Failure = 0;
                }

                var failOutputs = _nodes[_nodes[nextState].Failure].Outputs;
                if (failOutputs != null)
                {
                    var nextNode = _nodes[nextState];
                    nextNode.Outputs ??= new List<int>(failOutputs.Count);
                    nextNode.Outputs.AddRange(failOutputs);
                }

                queue.Enqueue(nextState);
            }
        }
    }

    public void FindMatches(ReadOnlySpan<char> text, List<AhoCorasickMatch> destination)
    {
        int state = 0;
        for (int i = 0; i < text.Length; i++)
        {
            char ch = char.ToLowerInvariant(text[i]);
            while (state != 0 && (_nodes[state].Transitions == null || !_nodes[state].Transitions!.ContainsKey(ch)))
            {
                state = _nodes[state].Failure;
            }

            if (_nodes[state].Transitions != null && _nodes[state].Transitions!.TryGetValue(ch, out int next))
            {
                state = next;
            }

            var outputs = _nodes[state].Outputs;
            if (outputs != null)
            {
                for (int o = 0; o < outputs.Count; o++)
                {
                    int patIdx = outputs[o];
                    int patLen = _patternLengths[patIdx];
                    destination.Add(new AhoCorasickMatch(patIdx, i - patLen + 1, patLen));
                }
            }
        }
    }
}
