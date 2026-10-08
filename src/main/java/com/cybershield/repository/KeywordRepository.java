package com.cybershield.repository;

import com.cybershield.entity.KeywordEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface KeywordRepository extends JpaRepository<KeywordEntity, Long> {
    Optional<KeywordEntity> findByKeywordIgnoreCase(String keyword);
    boolean existsByKeywordIgnoreCase(String keyword);
    List<KeywordEntity> findByCategory(String category);
}
