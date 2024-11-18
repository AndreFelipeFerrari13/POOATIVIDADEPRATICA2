package com.project.kanban.repository;

import com.project.kanban.model.Task;
import com.project.kanban.model.User;
import com.project.kanban.utils.Status;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface TaskRepository extends JpaRepository<Task, Long> {
    List<Task> findByStatus(Status status);
}