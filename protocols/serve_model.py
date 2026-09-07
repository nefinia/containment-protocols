"""Modal-hosted vLLM server, reused from the epistemic-fingerprints project
(https://github.com/nefinia/epistemic-fingerprints/blob/main/personas/serve_model.py).

One shared endpoint for the whole team -- deploy once, everyone hits the
same URL, no per-collaborator API keys or billing. Swap MODEL_NAME below
once the team picks a model for the monitor/reviewer judgment calls;
Qwen2.5-7B-Instruct was right for free-text hypothesis generation in the
prior project but may not be the right size/quality tradeoff here.

Deploy: `modal deploy protocols/serve_model.py`
"""

import subprocess
import modal

MODEL_NAME = "Qwen/Qwen2.5-7B-Instruct"  # placeholder -- confirm with team
VLLM_PORT = 8000
MINUTES = 60

vllm_image = (
    modal.Image.from_registry(
        "nvidia/cuda:12.9.0-devel-ubuntu22.04",
        add_python="3.12",
    )
    .entrypoint([])
    .env({
        "VLLM_USE_FLASHINFER_SAMPLER": "0",
    })
    .uv_pip_install("vllm==0.21.0")
)

app = modal.App("containment-vllm-server")


@app.server(
    image=vllm_image,
    gpu=["A10G", "L4"],
    port=VLLM_PORT,
    startup_timeout=10 * MINUTES,
    scaledown_window=5 * MINUTES,
    # Bumped from epistemic-fingerprints' default of 10: several
    # collaborators and several replicated-monitor protocols will hit
    # this concurrently during the sprint, not one person sequentially.
    target_concurrency=20,
    unauthenticated=True,
)
class Server:

    @modal.enter()
    def start(self):
        cmd = [
            "vllm",
            "serve",
            MODEL_NAME,
            "--served-model-name",
            MODEL_NAME,
            "--host",
            "0.0.0.0",
            "--port",
            str(VLLM_PORT),
            "--gpu-memory-utilization",
            "0.90",
            "--max-model-len",
            "4096",
        ]

        print("Starting:", " ".join(cmd))
        self.process = subprocess.Popen(cmd)

    @modal.exit()
    def stop(self):
        self.process.terminate()
