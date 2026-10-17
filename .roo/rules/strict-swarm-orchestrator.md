---
name: strict-swarm-orchestrator
description: Quy chuẩn bắt buộc AI chính chỉ đóng vai trò Tổng chỉ huy (Orchestrator). Cấm tuyệt đối tự làm thủ công đơn luồng, bắt buộc phải phân rã bài toán và gọi mcp--antigravity-swarm để giao việc cho các Worker AI song song.
---

# UNIVERSAL SWARM ORCHESTRATOR PROTOCOL (#universal-swarm)

Mandatory protocol to maximize development velocity and throughput by fully leveraging the Antigravity Swarm MCP proxy (`dispatch_parallel_workers` / `swarm_server`) across all software projects, programming languages, and task types.

---

## 1. HARD MANDATE (NON-NEGOTIABLE RULES)

- **FORBIDDEN TO EXECUTE SEQUENTIALLY WHEN PARALLEL IS POSSIBLE:** Whenever a task involves system analysis, architecture design, configuration writing, documentation generation, multi-module coding, or test suite compilation for any project, the Agent **MUST** break down the task into a list of independent sub-tasks and invoke the `dispatch_parallel_workers` tool from the `antigravity-swarm` / `swarm_server` server.
- **FORBIDDEN TO FALL BACK TO MANUAL MODE:** Do not manually write code, modify configuration files, or handle files sequentially in a single thread if the work can be delegated to 2 to 10 AI workers concurrently in seconds.
- **ORCHESTRATOR / GENERAL COMMANDER ROLE:** The main Agent acts strictly as the Chief Architect / General Commander:
  1. **Deconstruct** the problem/project into 3 to 8 independent modules or tasks.
  2. **Dispatch** the task list into `dispatch_parallel_workers` / `swarm_server`.
  3. **Receive** all parallel outputs simultaneously.
  4. **Integrate** the source code into the project workspace and perform verification/testing.

---

## 2. UNIVERSAL SWARM SPLIT PATTERN

Whenever deploying a new feature, a new module, or performing system refactoring:

| Worker | Specialized Task | Required Output |
| :--- | :--- | :--- |
| **Worker #1** | **Config & Schema** | Complete configuration files (`.json`, `.yaml`, `.env`, database schemas), clean, adhering to best practices. |
| **Worker #2** | **Core Logic & Business Operations** | Algorithmic implementations, business logic, service layers, utility functions. |
| **Worker #3** | **UI / API Endpoints / Components** | Source code for UI components, API routes, controllers, views. |
| **Worker #4** | **Test Suite (Automated Testing)** | Unit tests and integration tests achieving comprehensive logic and edge-case coverage. |
| **Worker #5** | **Documentation, Architecture & Refactoring** | System design documentation, API docs, code review reports, optimization strategies. |

---

## 3. DISPATCH CHECKLIST

- [ ] 1. Are the tasks submitted to `dispatch_parallel_workers` / `swarm_server` highly independent? (Does each worker solve its assigned domain completely without depending on real-time outputs from other workers?)
- [ ] 2. Have the requirements for each worker specified the expected format, programming language, framework, and coding standards?
- [ ] 3. After receiving parallel outputs, has the code been integrated, assembled, and verified via test suites to ensure 100% success?