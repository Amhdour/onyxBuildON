]633;E;echo "# Step 3 Setup Command Discovery";9d61e1fb-4bd8-40de-95d2-6be0c46dd04c]633;C# Step 3 Setup Command Discovery

Date: Mon May 25 09:55:42 UTC 2026
Branch: security-layer-mvp
Commit: 12df64c15e12ea8fac0fac92a7d6b1a9829025c6

## Candidate setup commands found in repo docs
backend/onyx/server/features/build/sandbox/kubernetes/kubernetes_sandbox_manager.py:        check_node_modules: If True, check for node_modules and run npm install if missing
backend/onyx/server/features/build/sandbox/kubernetes/kubernetes_sandbox_manager.py:    npm install
backend/onyx/server/features/build/sandbox/kubernetes/kubernetes_sandbox_manager.py:    cd {session_path}/outputs/web && npm install
backend/onyx/server/features/build/sandbox/kubernetes/kubernetes_sandbox_manager.py:        # Build NextJS startup script (npm install already done in outputs_setup).
backend/onyx/server/features/build/sandbox/kubernetes/docker/skills/pptx/SKILL.md:- `npm install -g pptxgenjs` - creating from scratch
backend/onyx/server/features/build/sandbox/kubernetes/docker/skills/pptx/pptxgenjs.md:Install: `npm install -g react-icons react react-dom sharp`
backend/onyx/server/features/build/sandbox/kubernetes/docker/Dockerfile:RUN npm install -g pptxgenjs && \
backend/onyx/server/features/build/sandbox/README.md:   - For self-hosted `docker compose` deployments enabled by `install.sh --include-craft`
backend/onyx/server/features/build/sandbox/README.md:- **Sandbox startup**: Runs `npm install` (for fresh dependency locks) + `next dev`
backend/onyx/server/features/build/sandbox/README.md:3. `npm install` runs automatically to install fresh Next.js dependencies
backend/onyx/server/features/build/sandbox/README.md:**Symptoms**: Sandbox status never changes from `PROVISIONING` in `docker compose` deployments
backend/onyx/server/features/build/sandbox/README.md:- Confirm `api_server` actually has the Docker socket: `docker compose exec api_server ls -l /var/run/docker.sock`
backend/onyx/server/features/build/sandbox/README.md:- Verify npm install succeeded (check entrypoint.sh logs)
backend/onyx/server/features/build/sandbox/docker/docker_sandbox_manager.py:    npm install
backend/onyx/server/features/build/sandbox/docker/docker_sandbox_manager.py:    cd {session_path}/outputs/web && npm install
backend/onyx/server/features/build/AGENTS.template.md:Install packages: `pip install <pkg>` or `npm install <pkg>` (from `outputs/web`).
backend/onyx/prompts/coding_agent/coding_agent.py:- Network commands (`curl`, `pip install`, `npm install`, `git pull`) — the sandbox has no network.
backend/scripts/restart_containers.sh:  docker compose -f "$COMPOSE_FILE" -f "$COMPOSE_DEV_FILE" --profile opensearch-enabled stop opensearch 2>/dev/null || true
backend/scripts/restart_containers.sh:  docker compose -f "$COMPOSE_FILE" -f "$COMPOSE_DEV_FILE" --profile opensearch-enabled rm -f opensearch 2>/dev/null || true
backend/scripts/restart_containers.sh:docker compose -f "$COMPOSE_FILE" -f "$COMPOSE_DEV_FILE" --profile opensearch-enabled up --force-recreate -d opensearch
backend/scripts/setup_craft_templates.sh:# 2. Run npm install in web template
backend/scripts/setup_craft_templates.sh:        cd "$WEB_TEMPLATE_PATH" && npm install 2>&1 || { echo "ERROR: npm install failed" >&2; exit 1; }
backend/scripts/sources_selection_analysis.py:            "It should be '3000' for local dev and '80' if Onyx runs using docker compose."
backend/tests/regression/answer_quality/cli_utils.py:        f"docker compose -f docker-compose.search-testing.yml -p onyx-{env_name} up -d"
backend/tests/external_dependency_unit/cache/conftest.py:    """Initialize DB engine. Assumes Postgres has migrations applied (e.g. via docker compose)."""
backend/tests/integration/README.md:docker compose -f docker-compose.mock-it-services.yml -p mock-it-services-stack up -d
backend/tests/integration/Dockerfile:RUN uv pip install --system --no-cache-dir --no-deps --require-hashes -r /tmp/dev-requirements.txt && \
backend/Dockerfile.model_server:        | uv pip install --system --no-cache-dir --no-deps --require-hashes -r /dev/stdin && \
backend/Dockerfile.model_server:RUN uv pip install --system --no-cache-dir --no-deps --require-hashes \
backend/Dockerfile:RUN uv pip install --system --no-cache-dir --no-deps --require-hashes \
backend/Dockerfile:# pip/npm install only invalidates on its own inputs, not on every PR.
backend/requirements/README.md:artifact. Docker builds and CI install with `uv pip install --require-hashes`,
backend/requirements/README.md:uv sync
backend/requirements/README.md:uv sync --no-default-groups --group backend
backend/requirements/README.md:uv sync --no-default-groups --group model_server
docs/craft/features/bun-node-modules-dedup.md:Each Craft session in a sandbox currently runs `npm install` against the
docs/craft/features/bun-node-modules-dedup.md:| `npm install` wall time | ~30 s |
docs/craft/features/bun-node-modules-dedup.md:2. ~30 s of cold-start latency per session, dominated by `npm install`.
docs/craft/features/bun-node-modules-dedup.md:3. Agent-driven `npm install <new-pkg>` mid-session must continue to work
docs/craft/features/bun-node-modules-dedup.md:We replace `npm install` with `bun install` and structure
docs/craft/features/bun-node-modules-dedup.md:- **Speed**: `bun install` is typically 10–25× faster than `npm install`.
docs/craft/features/bun-node-modules-dedup.md:  - Replace `cd outputs/web && npm install` with `cd outputs/web && bun install --frozen-lockfile`
docs/craft/features/docker-sandbox-backend.md:Main goal: make Onyx Craft package cleanly for `docker compose` deployments with a containerized sandbox backend, while keeping the implementation as close as practical to the current Kubernetes Craft architecture.
docs/craft/legacy/sandbox-backends.md:Give self-hosted Onyx a sandbox backend that's actually isolated. Today there are two backends: `local` (a directory on the host with no container boundary) and `kubernetes` (real pod isolation, but requires a K8s cluster). The middle ground is missing — a self-hosted admin who runs the standard `docker compose up` deployment has no way to run Craft sessions safely. They get `local`, which means the agent's bash tool runs as the api_server user, on the host. That's fine for a dev laptop and unacceptable for a real team.
docs/craft/legacy/sandbox-backends.md:- **`local` retained for dev, never marketed as secure.** Update `sandbox/README.md`, `configs.py`, and the env template to make the role of each backend explicit. Default for `docker compose` deployments shifts to `docker`. Default for plain `python -m onyx.main` (running outside containers) stays `local`.
docs/craft/legacy/sandbox-backends.md:   - Running `docker compose up` (the supported self-hosted path): `docker`.
docs/craft/legacy/sandbox-backends.md:11. **Docker socket access is documented as the trust boundary.** Self-hosted admins who don't want to mount the socket are explicitly told to keep `SANDBOX_BACKEND=local` and accept the loss of isolation. The docker-compose default assumes the admin chose `docker compose up` and is fine giving the api_server access to Docker — same trust delta as giving the api_server access to the host's filesystem already.
docs/craft/legacy/sandbox-backends.md:- Bring up `docker compose up` with `SANDBOX_BACKEND=docker` and `ENABLE_CRAFT=true`. Mount the socket. Run a Craft session end-to-end: create a session, send a prompt, watch the agent run, view the produced artifact. Confirm the container appears under `docker ps`, the session directory under `docker exec sandbox-<id> ls /workspace/sessions/`, and the volume under `docker volume ls`.
docs/craft/legacy/interception.md:- `docker compose up` with `SANDBOX_BACKEND=docker` and `ENABLE_CRAFT=true`. Confirm the `onyx-craft-egress` container is up. Open a Craft session, run an OpenCode skill that does `curl -v https://httpbin.org/headers`. Confirm:
docs/craft/infra/sandbox-daemon-expansion.md:| `setup_session_workspace` | Creates session dir, copies template, npm install, symlinks skills, writes AGENTS.md + opencode.json + org_info, starts Next.js | `POST /session/setup` (single call carrying config payload) |
docs/craft/infra/sandbox-daemon-expansion.md:→ Creates session dir, copies outputs template, runs npm install, symlinks
docs/security/evidence/step3_setup_command_discovery.md:backend/onyx/server/features/build/sandbox/kubernetes/kubernetes_sandbox_manager.py:        check_node_modules: If True, check for node_modules and run npm install if missing
docs/security/evidence/step3_setup_command_discovery.md:backend/onyx/server/features/build/sandbox/kubernetes/kubernetes_sandbox_manager.py:    npm install
docs/security/evidence/step3_setup_command_discovery.md:backend/onyx/server/features/build/sandbox/kubernetes/kubernetes_sandbox_manager.py:    cd {session_path}/outputs/web && npm install
docs/security/evidence/step3_setup_command_discovery.md:backend/onyx/server/features/build/sandbox/kubernetes/kubernetes_sandbox_manager.py:        # Build NextJS startup script (npm install already done in outputs_setup).
docs/security/evidence/step3_setup_command_discovery.md:backend/onyx/server/features/build/sandbox/kubernetes/docker/skills/pptx/SKILL.md:- `npm install -g pptxgenjs` - creating from scratch
docs/security/evidence/step3_setup_command_discovery.md:backend/onyx/server/features/build/sandbox/kubernetes/docker/skills/pptx/pptxgenjs.md:Install: `npm install -g react-icons react react-dom sharp`
docs/security/evidence/step3_setup_command_discovery.md:backend/onyx/server/features/build/sandbox/kubernetes/docker/Dockerfile:RUN npm install -g pptxgenjs && \
docs/security/evidence/step3_setup_command_discovery.md:backend/onyx/server/features/build/sandbox/README.md:   - For self-hosted `docker compose` deployments enabled by `install.sh --include-craft`
docs/security/evidence/step3_setup_command_discovery.md:backend/onyx/server/features/build/sandbox/README.md:- **Sandbox startup**: Runs `npm install` (for fresh dependency locks) + `next dev`
docs/security/evidence/step3_setup_command_discovery.md:backend/onyx/server/features/build/sandbox/README.md:3. `npm install` runs automatically to install fresh Next.js dependencies
docs/security/evidence/step3_setup_command_discovery.md:backend/onyx/server/features/build/sandbox/README.md:**Symptoms**: Sandbox status never changes from `PROVISIONING` in `docker compose` deployments
docs/security/evidence/step3_setup_command_discovery.md:backend/onyx/server/features/build/sandbox/README.md:- Confirm `api_server` actually has the Docker socket: `docker compose exec api_server ls -l /var/run/docker.sock`
docs/security/evidence/step3_setup_command_discovery.md:backend/onyx/server/features/build/sandbox/README.md:- Verify npm install succeeded (check entrypoint.sh logs)
docs/security/evidence/step3_setup_command_discovery.md:backend/onyx/server/features/build/sandbox/docker/docker_sandbox_manager.py:    npm install
docs/security/evidence/step3_setup_command_discovery.md:backend/onyx/server/features/build/sandbox/docker/docker_sandbox_manager.py:    cd {session_path}/outputs/web && npm install
docs/security/evidence/step3_setup_command_discovery.md:backend/onyx/server/features/build/AGENTS.template.md:Install packages: `pip install <pkg>` or `npm install <pkg>` (from `outputs/web`).
docs/security/evidence/step3_setup_command_discovery.md:backend/onyx/prompts/coding_agent/coding_agent.py:- Network commands (`curl`, `pip install`, `npm install`, `git pull`) — the sandbox has no network.
docs/security/evidence/step3_setup_command_discovery.md:backend/scripts/restart_containers.sh:  docker compose -f "$COMPOSE_FILE" -f "$COMPOSE_DEV_FILE" --profile opensearch-enabled stop opensearch 2>/dev/null || true
docs/security/evidence/step3_setup_command_discovery.md:backend/scripts/restart_containers.sh:  docker compose -f "$COMPOSE_FILE" -f "$COMPOSE_DEV_FILE" --profile opensearch-enabled rm -f opensearch 2>/dev/null || true
docs/security/evidence/step3_setup_command_discovery.md:backend/scripts/restart_containers.sh:docker compose -f "$COMPOSE_FILE" -f "$COMPOSE_DEV_FILE" --profile opensearch-enabled up --force-recreate -d opensearch
docs/security/evidence/step3_setup_command_discovery.md:backend/scripts/setup_craft_templates.sh:# 2. Run npm install in web template
docs/security/evidence/step3_setup_command_discovery.md:backend/scripts/setup_craft_templates.sh:        cd "$WEB_TEMPLATE_PATH" && npm install 2>&1 || { echo "ERROR: npm install failed" >&2; exit 1; }
docs/security/evidence/step3_setup_command_discovery.md:backend/scripts/sources_selection_analysis.py:            "It should be '3000' for local dev and '80' if Onyx runs using docker compose."
docs/security/evidence/step3_setup_command_discovery.md:backend/tests/regression/answer_quality/cli_utils.py:        f"docker compose -f docker-compose.search-testing.yml -p onyx-{env_name} up -d"
docs/security/evidence/step3_setup_command_discovery.md:backend/tests/external_dependency_unit/cache/conftest.py:    """Initialize DB engine. Assumes Postgres has migrations applied (e.g. via docker compose)."""
docs/security/evidence/step3_setup_command_discovery.md:backend/tests/integration/README.md:docker compose -f docker-compose.mock-it-services.yml -p mock-it-services-stack up -d
docs/security/evidence/step3_setup_command_discovery.md:backend/tests/integration/Dockerfile:RUN uv pip install --system --no-cache-dir --no-deps --require-hashes -r /tmp/dev-requirements.txt && \
docs/security/evidence/step3_setup_command_discovery.md:backend/Dockerfile.model_server:        | uv pip install --system --no-cache-dir --no-deps --require-hashes -r /dev/stdin && \
docs/security/evidence/step3_setup_command_discovery.md:backend/Dockerfile.model_server:RUN uv pip install --system --no-cache-dir --no-deps --require-hashes \
