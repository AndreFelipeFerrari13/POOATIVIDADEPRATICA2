package com.project.kanban.service;

import com.project.kanban.model.Task;
import com.project.kanban.repository.TaskRepository;
import com.project.kanban.utils.Priority;
import com.project.kanban.utils.Status;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class TaskService {

    private final TaskRepository taskRepository;

    public TaskService(TaskRepository taskRepository) {
        this.taskRepository = taskRepository;
    }

    public List<Task> getAllTasks() {
        return taskRepository.findAll();
    }

    public Task createTask(Task task) {
        task.setStatus(Status.TODO);
        task.setCreatedAt(LocalDate.now());
        return taskRepository.save(task);
    }

    public Optional<Task> getTaskById(Long id) {
        return taskRepository.findById(id);
    }

    public Task updateTask(Task task) {
        return taskRepository.save(task);
    }

    public void deleteTask(Long id) {
        taskRepository.deleteById(id);
    }

    @Transactional
    public Task moveTask(Long id) {
        Task task = taskRepository.findById(id).orElseThrow(() -> new IllegalArgumentException("Tarefa não encontrada"));
        switch (task.getStatus()) {
            case Status.TODO:
                task.setStatus(Status.DOING);
                break;
            case Status.DOING:
                task.setStatus(Status.DONE);
                break;
            case Status.DONE:
                throw new IllegalStateException("Tarefa já concluída");
        }
        return task;
    }

    public List<Task> getTasksSortedByPriority(Status status) {
        return taskRepository.findByStatus(status).stream()
                .sorted(Comparator.comparing(Task::getPriority))
                .collect(Collectors.toList());
    }

    public List<Task> filterTasks(String priority, String deadline) {
        return taskRepository.findAll().stream()
                .filter(task -> {
                    if (priority == null) return true;
                    try {
                        return task.getPriority() == Priority.valueOf(priority.toUpperCase());
                    } catch (IllegalArgumentException e) {
                        return false;
                    }
                })
                .filter(task -> {
                    if (deadline == null) return true;
                    LocalDate parsedDeadline = LocalDate.parse(deadline);
                    return task.getDeadline() != null && task.getDeadline().isBefore(parsedDeadline);
                })
                .collect(Collectors.toList());
    }


    public Map<Status, List<Task>> generateReport() {
        Map<Status, List<Task>> report = new HashMap<>();

        List<Status> columns = List.of(Status.TODO, Status.DOING);
        for (Status column : columns) {
            List<Task> overdueTasks = taskRepository.findByStatus(column).stream()
                    .filter(task -> task.getDeadline() != null)
                    .filter(task -> task.getDeadline().isBefore(LocalDateTime.now().toLocalDate()))
                    .collect(Collectors.toList());

            report.put(column, overdueTasks);
        }

        return report;
    }


}