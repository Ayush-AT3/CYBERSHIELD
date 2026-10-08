package com.cybershield.service.layer1;

import com.cybershield.model.PhishingKeyword;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class AhoCorasickNode {
    private final Map<Character, AhoCorasickNode> children = new HashMap<>();
    private AhoCorasickNode failureLink;
    private final List<PhishingKeyword> outputs = new ArrayList<>();

    public Map<Character, AhoCorasickNode> getChildren() {
        return children;
    }

    public AhoCorasickNode getChild(char c) {
        return children.get(c);
    }

    public void addChild(char c, AhoCorasickNode node) {
        children.put(c, node);
    }

    public AhoCorasickNode getFailureLink() {
        return failureLink;
    }

    public void setFailureLink(AhoCorasickNode failureLink) {
        this.failureLink = failureLink;
    }

    public List<PhishingKeyword> getOutputs() {
        return outputs;
    }

    public void addOutput(PhishingKeyword keyword) {
        this.outputs.add(keyword);
    }

    public void addOutputs(List<PhishingKeyword> extraOutputs) {
        this.outputs.addAll(extraOutputs);
    }
}
