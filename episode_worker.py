import os
import json
import time
import uuid
import shutil
import subprocess
import tempfile
from pathlib import Path
from datetime import datetime

import boto3


def load_local_env(path=".env.r2.local"):
    env_file = Path(path)

    if not env_file.exists():
        return

    for raw_line in env_file.read_text().splitlines():
        line = raw_line.strip()

        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()

        if (
            len(value) >= 2
            and value[0] == value[-1]
            and value[0] in ("\\\"", "'")
        ):
            value = value[1:-1]

        os.environ.setdefault(key, value)


load_local_env()


R2_ACCOUNT_ID = os.getenv("R2_ACCOUNT_ID", "").strip()
R2_ACCESS_KEY_ID = os.getenv("R2_ACCESS_KEY_ID", "").strip()
R2_SECRET_ACCESS_KEY = os.getenv("R2_SECRET_ACCESS_KEY", "").strip()
R2_BUCKET_NAME = os.getenv("R2_BUCKET_NAME", "").strip()
R2_PUBLIC_URL = os.getenv("R2_PUBLIC_URL", "").rstrip("/")

if not all([
    R2_ACCOUNT_ID,
    R2_ACCESS_KEY_ID,
    R2_SECRET_ACCESS_KEY,
    R2_BUCKET_NAME
]):
    raise RuntimeError("R2 environment variables are missing")


R2_ENDPOINT = (
    f"https://{R2_ACCOUNT_ID}.r2.cloudflarestorage.com"
)

r2 = boto3.client(
    "s3",
    endpoint_url=R2_ENDPOINT,
    aws_access_key_id=R2_ACCESS_KEY_ID,
    aws_secret_access_key=R2_SECRET_ACCESS_KEY,
    region_name="auto",
)


EPISODE_LENGTH = 150


def now():
    return datetime.now().isoformat(timespec="seconds")


def load_catalog():
    response = r2.get_object(
        Bucket=R2_BUCKET_NAME,
        Key="data/catalog.json"
    )

    return json.loads(
        response["Body"].read().decode("utf-8")
    )


def save_catalog(data):
    r2.put_object(
        Bucket=R2_BUCKET_NAME,
        Key="data/catalog.json",
        Body=json.dumps(
            data,
            indent=2,
            ensure_ascii=False
        ).encode("utf-8"),
        ContentType="application/json"
    )


def public_url(key):
    return f"{R2_PUBLIC_URL}/{key}"


def run_ffmpeg(source, output, start, duration):
    command = [
        "ffmpeg",
        "-hide_banner",
        "-loglevel",
        "error",

        "-ss",
        str(start),

        "-i",
        str(source),

        "-t",
        str(duration),

        "-map",
        "0",

        "-c",
        "copy",

        "-avoid_negative_ts",
        "make_zero",

        "-movflags",
        "+faststart",

        "-y",
        str(output)
    ]

    subprocess.run(
        command,
        check=True
    )


def upload_episode(path, key):
    content_type = "video/mp4"

    r2.upload_file(
        str(path),
        R2_BUCKET_NAME,
        key,
        ExtraArgs={
            "ContentType": content_type
        }
    )

    return public_url(key)


def find_next_job(data):
    for job in data.get("episode_jobs", []):

        if job.get("type") != "episode_split":
            continue

        if job.get("status") != "queued":
            continue

        return job

    return None


def process_job(job):
    job_id = job["id"]

    source_key = job["source_key"]
    drama_id = job["drama_id"]
    segments = job.get("segments", [])

    print(
        f"[{job_id}] "
        f"Starting {len(segments)} episode(s)"
    )

    work_dir = Path(
        tempfile.mkdtemp(
            prefix="episode-worker-"
        )
    )

    source_path = work_dir / "source"

    try:

        # Claim the job in R2 before doing any video work.
        data = load_catalog()

        stored_job = next(
            (
                x for x in data.get("episode_jobs", [])
                if x.get("id") == job_id
            ),
            None
        )

        if not stored_job:
            raise RuntimeError("Job disappeared from catalog")

        if stored_job.get("status") not in ("queued", "processing"):
            print(
                f"[{job_id}] Job is already "
                f"{stored_job.get('status')}; skipping."
            )
            return

        # Only the worker that sees this queued job should claim it.
        if stored_job.get("status") == "queued":
            stored_job["status"] = "processing"
            stored_job["progress"] = 0
            stored_job["updated_at"] = now()
            save_catalog(data)

        # Refresh the claimed job.
        data = load_catalog()

        stored_job = next(
            (
                x for x in data.get("episode_jobs", [])
                if x.get("id") == job_id
            ),
            None
        )

        if not stored_job:
            raise RuntimeError("Claimed job disappeared")

        if stored_job.get("status") != "processing":
            print(
                f"[{job_id}] Job is no longer processing; "
                f"stopping."
            )
            return

        print(
            f"[{job_id}] Downloading source: "
            f"{source_key}"
        )

        r2.download_file(
            R2_BUCKET_NAME,
            source_key,
            str(source_path)
        )

        total = len(segments)

        for index, segment in enumerate(
            segments,
            start=1
        ):

            number = int(
                segment["number"]
            )

            start = float(
                segment["start"]
            )

            end = float(
                segment["end"]
            )

            duration = end - start

            output_path = (
                work_dir
                / f"episode-{number:04d}.mp4"
            )

            print(
                f"[{job_id}] "
                f"Episode {number}: "
                f"{start:.3f}s -> "
                f"{end:.3f}s"
            )

            run_ffmpeg(
                source_path,
                output_path,
                start,
                duration
            )

            key = (
                f"episodes/"
                f"{drama_id}/"
                f"{uuid.uuid4().hex}.mp4"
            )

            url = upload_episode(
                output_path,
                key
            )

            data = load_catalog()

            episode = {
                "id": uuid.uuid4().hex,
                "drama_id": drama_id,
                "number": number,
                "title": segment.get(
                    "title"
                ) or f"Episode {number}",
                "video": url,
                "video_url": url,
                "video_key": key,
                "thumbnail": segment.get(
                    "thumbnail"
                ) or "",
                "created_at": now(),
                "updated_at": now(),
                "views": 0
            }

            data.setdefault(
                "episodes",
                []
            )

            data["episodes"].append(
                episode
            )

            # Mark this segment complete.
            for stored in data.get(
                "episode_jobs",
                []
            ):
                if stored.get("id") == job_id:
                    stored["segments"][
                        index - 1
                    ]["status"] = "completed"

                    stored["segments"][
                        index - 1
                    ]["video"] = url

                    stored["progress"] = int(
                        index / total * 100
                    )

                    stored["updated_at"] = now()

                    if index == total:
                        stored["status"] = "completed"

            save_catalog(data)

            print(
                f"[{job_id}] "
                f"Episode {number} uploaded."
            )

            try:
                output_path.unlink()
            except FileNotFoundError:
                pass

        print(
            f"[{job_id}] "
            f"Completed successfully."
        )

    except Exception as exc:

        print(
            f"[{job_id}] ERROR: {exc}"
        )

        data = load_catalog()

        for stored in data.get(
            "episode_jobs",
            []
        ):
            if stored.get("id") == job_id:
                stored["status"] = "failed"
                stored["error"] = str(exc)
                stored["updated_at"] = now()

        save_catalog(data)

        raise

    finally:
        shutil.rmtree(
            work_dir,
            ignore_errors=True
        )


def main():
    print(
        "Short Reels Episode Worker started."
    )

    while True:

        try:
            data = load_catalog()
            job = find_next_job(data)

            if job:
                try:
                    process_job(job)
                except Exception as exc:
                    print(
                        "Job failed:",
                        exc
                    )
            else:
                time.sleep(5)

        except Exception as exc:
            print(
                "Worker error:",
                exc
            )

            time.sleep(10)


if __name__ == "__main__":
    main()
