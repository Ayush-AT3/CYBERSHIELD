package com.cybershield.repository;

import com.cybershield.entity.ScanRecordEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface ScanRecordRepository extends JpaRepository<ScanRecordEntity, Long> {
    List<ScanRecordEntity> findTop20ByOrderByCreatedAtDesc();
    Optional<ScanRecordEntity> findByScanId(String scanId);
    long countByClassification(String classification);
}
