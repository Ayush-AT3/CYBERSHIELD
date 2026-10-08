package com.cybershield.service.layer1;

import com.cybershield.model.PhishingKeyword;

import java.util.*;

public class AhoCorasickEngine {
    private final AhoCorasickNode root = new AhoCorasickNode();

    public static class Match {
        private final PhishingKeyword keyword;
        private final int startIndex;
        private final int endIndex;

        public Match(PhishingKeyword keyword, int startIndex, int endIndex) {
            this.keyword = keyword;
            this.startIndex = startIndex;
            this.endIndex = endIndex;
        }

        public PhishingKeyword getKeyword() {
            return keyword;
        }

        public int getStartIndex() {
            return startIndex;
        }

        public int getEndIndex() {
            return endIndex;
        }
    }

    public void buildTrie(Collection<PhishingKeyword> keywords) {
        if (keywords == null) return;

        // Step 1: Insert all keywords into Trie
        for (PhishingKeyword pk : keywords) {
            if (pk.getKeyword() == null || pk.getKeyword().trim().isEmpty()) continue;
            String text = pk.getKeyword().trim().toLowerCase();
            AhoCorasickNode current = root;
            for (char c : text.toCharArray()) {
                current = current.getChildren().computeIfAbsent(c, k -> new AhoCorasickNode());
            }
            current.addOutput(pk);
        }

        // Step 2: Build failure and output transitions via BFS
        Queue<AhoCorasickNode> queue = new ArrayDeque<>();
        for (AhoCorasickNode child : root.getChildren().values()) {
            child.setFailureLink(root);
            queue.add(child);
        }

        while (!queue.isEmpty()) {
            AhoCorasickNode current = queue.poll();

            for (Map.Entry<Character, AhoCorasickNode> entry : current.getChildren().entrySet()) {
                char ch = entry.getKey();
                AhoCorasickNode child = entry.getValue();

                AhoCorasickNode fail = current.getFailureLink();
                while (fail != null && !fail.getChildren().containsKey(ch)) {
                    fail = fail.getFailureLink();
                }

                AhoCorasickNode fallback = (fail != null) ? fail.getChild(ch) : root;
                child.setFailureLink(fallback != null ? fallback : root);

                // Inherit outputs from failure link
                if (child.getFailureLink() != null) {
                    child.addOutputs(child.getFailureLink().getOutputs());
                }

                queue.add(child);
            }
        }
    }

    public List<Match> search(String text) {
        List<Match> matches = new ArrayList<>();
        if (text == null || text.isEmpty()) return matches;

        String lowerText = text.toLowerCase();
        AhoCorasickNode current = root;

        for (int i = 0; i < lowerText.length(); i++) {
            char c = lowerText.charAt(i);

            while (current != root && !current.getChildren().containsKey(c)) {
                current = current.getFailureLink();
                if (current == null) current = root;
            }

            current = current.getChild(c);
            if (current == null) {
                current = root;
            }

            for (PhishingKeyword output : current.getOutputs()) {
                int start = i - output.getKeyword().length() + 1;
                matches.add(new Match(output, start, i + 1));
            }
        }

        return matches;
    }
}
