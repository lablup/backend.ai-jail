import os
import subprocess
from datetime import datetime
from pathlib import Path

GITHUB_BOT_EMAIL = (
    "github-actions[bot] <41898282+github-actions[bot]@users.noreply.github.com>"
)

branch_name = str(hash(datetime.now().timestamp()))


def run(command):
    subprocess.run(command, check=True, shell=True, cwd=Path.cwd())


run(f"git checkout -b {branch_name}")
run(f"git add ./default-policies/*")
run(
    f'GIT_COMMITTER_NAME="PROFILE_UPDATE_BOT" git commit --author="{GITHUB_BOT_EMAIL}" -m "Update Seccomp Default Profiles"',
)
run(f"git push origin {branch_name}")

PR_TITLE = "chore: bump default policy update"
PR_BODY = "Bumps [seccomp default policy](https://raw.githubusercontent.com/moby/moby/master/profiles/seccomp/default.json) update"

run(
    " ".join(
        [
            f'GITHUB_TOKEN={os.environ["GH_TOKEN"]}',
            f"gh pr create",
            f'--title "{PR_TITLE}"',
            f'--body "{PR_BODY}"',
            f'--repo "lablup/backend.ai-jail"',
            f'--base "main"',
            f'--label "infrastructure"',
            # TODO: Remove below flag.
            f"--draft",
        ]
    )
)
