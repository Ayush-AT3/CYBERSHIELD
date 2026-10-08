package com.cybershield.service.layer3;

import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

@Component
public class ShannonEntropyCalculator {

    public double calculateEntropy(String input) {
        if (input == null || input.isEmpty()) {
            return 0.0;
        }

        Map<Character, Integer> frequencyMap = new HashMap<>();
        for (char c : input.toCharArray()) {
            frequencyMap.put(c, frequencyMap.getOrDefault(c, 0) + 1);
        }

        int length = input.length();
        double entropy = 0.0;

        for (Map.Entry<Character, Integer> entry : frequencyMap.entrySet()) {
            double probability = (double) entry.getValue() / length;
            entropy -= probability * (Math.log(probability) / Math.log(2));
        }

        return Math.round(entropy * 100.0) / 100.0;
    }

    public boolean isHighEntropy(String input, double threshold) {
        return calculateEntropy(input) >= threshold;
    }
}
