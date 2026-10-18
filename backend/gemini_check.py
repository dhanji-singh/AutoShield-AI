import json
import os
import re
import sys
from urllib.error import HTTPError, URLError
from urllib.request import (
    HTTPRedirectHandler,
    Request,
    build_opener,
)


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def main():
    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    model = os.getenv(
        "GEMINI_MODEL",
        "gemini-2.5-flash-lite",
    ).strip()

    if not api_key:
        print("ERROR: GEMINI_API_KEY is missing.")
        return 1

    if not re.fullmatch(r"[a-zA-Z0-9._-]+", model):
        print("ERROR: Invalid GEMINI_MODEL value.")
        return 1

    url = (
        "https://generativelanguage.googleapis.com/v1beta/"
        f"models/{model}:generateContent"
    )

    payload = {
        "contents": [
            {
                "role": "user",
                "parts": [
                    {
                        "text": "Reply with exactly: AutoShield AI connected"
                    }
                ],
            }
        ],
        "generationConfig": {
            "temperature": 0,
            "maxOutputTokens": 64,
        },
    }

    request = Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "x-goog-api-key": api_key,
        },
        method="POST",
    )

    opener = build_opener(NoRedirects())

    try:
        with opener.open(request, timeout=30) as response:
            result = json.load(response)

    except HTTPError as exc:
        code = exc.code

        try:
            error_body = json.loads(exc.read(16384))
            message = str(
                error_body.get("error", {}).get(
                    "message",
                    "Gemini rejected the request.",
                )
            )
        except (ValueError, AttributeError):
            message = "Gemini rejected the request."
        finally:
            exc.close()

        # Never print the API key, even if included in an error.
        message = message.replace(api_key, "[REDACTED]")

        print(f"Gemini API error: HTTP {code}")
        print(message[:1200])

        if code == 429:
            print("Check the project's rate limits and available quota.")
        elif code in (400, 401, 403):
            print("Check API-key validity, permissions and project eligibility.")
        elif code == 404:
            print("The configured model may be unavailable for this API.")

        return 1

    except (URLError, TimeoutError, OSError):
        print("Connection failed or timed out. Check internet/Docker networking.")
        return 1

    except ValueError:
        print("Gemini returned an unreadable JSON response.")
        return 1

    candidates = result.get("candidates", [])

    if not candidates:
        print("No response candidate returned.")
        print("Prompt feedback:", result.get("promptFeedback", {}))
        return 1

    candidate = candidates[0]

    text = "".join(
        part.get("text", "")
        for part in candidate.get("content", {}).get("parts", [])
        if not part.get("thought", False)
    ).strip()

    if not text:
        print("No text response returned.")
        print("Finish reason:", candidate.get("finishReason", "unknown"))
        return 1

    print("Gemini API call succeeded.")
    print("Model:", model)
    print("Response:", text.replace(api_key, "[REDACTED]"))
    print(
        "Exact test phrase matched:",
        text == "AutoShield AI connected",
    )

    usage = result.get("usageMetadata", {})
    print("Reported total tokens:", usage.get("totalTokenCount", "unknown"))

    return 0


if __name__ == "__main__":
    sys.exit(main())