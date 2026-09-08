# app/input_validator.py

"""
Input validation and sanitization for email content.

This module is the first gate in the application flow. Before the system
analyses an email, it decides whether the user sent a file upload or pasted raw
content, then validates the input for missing data, unexpected file types,
unsafe characters, and obvious email-format issues.

The goal is simple: accept only usable email input and reject malformed or
suspicious requests with a clear HTTP error instead of letting invalid data reach
later analysis services.
"""

from enum import Enum
from typing import Tuple
import re
from fastapi import HTTPException


class InputMode(str, Enum):
    """Represents the source of the email content.

    This enum keeps the rest of the project consistent by labeling the input as
    either a file upload or raw pasted text. The selected mode is later used to
    decide which validation path to follow.
    """
    FILE_UPLOAD = "file"
    RAW_CONTENT = "raw"


class InputValidator:
    """Validates and sanitizes email input from different sources.

    The class is intentionally small and focused. Each method handles one piece
    of the problem: file checks, raw-text checks, payload cleanup, and a basic
    email-format sanity check. Together they protect the application from empty,
    invalid, or suspicious inputs before deeper parsing starts.
    """

    # Regex pattern for basic MIME structure detection.
    # It looks for common email headers such as From, To, Subject, and Date.
    MIME_PATTERN = re.compile(
        r'^(From:|To:|Subject:|Date:|Message-ID:|MIME-Version:|Content-Type:)',
        re.MULTILINE
    )
    
    # Max sizes
    MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB
    MAX_RAW_TEXT_SIZE = 100 * 1024 * 1024  # 100MB
    
    @staticmethod
    def validate_file_input(filename: str | None, data: bytes) -> Tuple[str, str]:
        """Validate and decode an uploaded .eml file.

        This is the file-based input path. The method first checks that a real
        file name exists, confirms the extension is .eml, and ensures the payload
        is not empty or too large. Once the file passes the structural checks, it
        decodes the raw bytes back into text so the rest of the email analysis
        pipeline can process it.

        Workflow:
        1. Reject missing or invalid file names.
        2. Enforce the .eml-only rule.
        3. Block oversized and empty uploads.
        4. Decode the raw data using UTF-8 first, then a fallback encoding.
        5. Return the source type and readable email content.

        Args:
            filename: The uploaded file name from the client.
            data: The raw file content as bytes.

        Returns:
            A tuple containing the input mode and the decoded email text.

        Raises:
            HTTPException: If the file is missing, invalid, too large, empty, or
                cannot be decoded into usable text.
        """
        # A file upload is only valid if the browser actually provides a name.
        if not filename:
            raise HTTPException(
                status_code=400,
                detail="File name missing. Please select a valid .eml file."
            )

        # Accept only email files to reduce accidental misuse.
        if not filename.lower().endswith('.eml'):
            raise HTTPException(
                status_code=400,
                detail=f"Invalid file extension. Only .eml files are allowed. Got: {filename.split('.')[-1]}"
            )

        # Prevent excessive memory usage from very large uploaded files.
        if len(data) > InputValidator.MAX_FILE_SIZE:
            raise HTTPException(
                status_code=413,
                detail=f"File too large. Maximum size is {InputValidator.MAX_FILE_SIZE / 1024 / 1024:.1f}MB"
            )

        # Empty uploads do not contain any email data.
        if len(data) == 0:
            raise HTTPException(
                status_code=400,
                detail="Uploaded file is empty."
            )

        # Decode the binary payload into a readable string. This keeps the app
        # resilient to slightly non-standard email encodings.
        try:
            content = data.decode("utf-8", errors="replace")
        except Exception:
            try:
                content = data.decode("latin1", errors="replace")
            except Exception as e:
                raise HTTPException(
                    status_code=400,
                    detail="Failed to decode file content. Ensure it's a valid email file."
                ) from e

        return InputMode.FILE_UPLOAD, content
    
    @staticmethod
    def validate_raw_content(content: str) -> Tuple[str, str]:
        """Validate and clean pasted email text.

        This method is used when the user pastes the email as plain text instead of
        uploading a file. It trims the content, rejects empty or oversized input,
        sanitizes suspicious characters, and then performs a light heuristic
        check to confirm it still resembles a real email message.

        The key idea is to keep the workflow simple: if the pasted text does not
        look like an email at all, the request is rejected early before the rest
        of the system tries to parse it.

        Args:
            content: The raw email body or full message pasted by the user.

        Returns:
            A tuple containing the input mode and the cleaned email text.

        Raises:
            HTTPException: If the input is empty, oversized, suspicious, or does
                not look like an email.
        """
        # Strip leading and trailing spaces so accidental whitespace does not
        # count as valid content.
        content = content.strip()

        # Empty text is not a valid email payload.
        if not content:
            raise HTTPException(
                status_code=400,
                detail="Please paste email content. Text area is empty."
            )

        # Prevent extremely large raw text from being processed.
        if len(content) > InputValidator.MAX_RAW_TEXT_SIZE:
            raise HTTPException(
                status_code=413,
                detail=f"Content too large. Maximum size is {InputValidator.MAX_RAW_TEXT_SIZE / 1024 / 1024:.1f}MB"
            )

        # Remove dangerous control characters while preserving the actual email
        # structure and message body.
        sanitized = InputValidator._sanitize_content(content)

        # This is a cheap but useful quality gate: a real email normally contains
        # standard headers such as From, To, Subject, or Date.
        if not InputValidator._looks_like_email(sanitized):
            raise HTTPException(
                status_code=400,
                detail="Content doesn't appear to be valid email format. "
                       "Expected standard email headers (From:, To:, Subject:, etc.)"
            )

        return InputMode.RAW_CONTENT, sanitized
    
    @staticmethod
    def _sanitize_content(content: str) -> str:
        """Clean out unsafe control characters from raw email text.

        This helper is intentionally conservative. It keeps normal text and tabs,
        but strips ASCII control characters that can be used for embedded
        injection tricks or malformed payloads. This helps protect later parsing
        logic without changing the visible email content too aggressively.

        Args:
            content: The original raw text as entered by the user.

        Returns:
            A cleaned string safe enough for downstream email analysis.
        """
        lines = content.split('\n')
        cleaned_lines = []

        for line in lines:
            # Remove characters below a standard printable space while allowing
            # tabs. This blocks null-byte and control-character injection.
            clean_line = ''.join(
                char for char in line
                if ord(char) >= 32 or char in '\t'
            )
            cleaned_lines.append(clean_line)

        return '\n'.join(cleaned_lines)
    
    @staticmethod
    def _looks_like_email(content: str) -> bool:
        """Run a quick header-based sanity check.

        This is not a full email parser; it is only a lightweight guardrail. If
        the content contains one of the usual headers such as From, To, Subject,
        or Date, it is likely an actual email message and can continue through the
        pipeline. If not, something is probably wrong with the input.

        Args:
            content: The cleaned email text to inspect.

        Returns:
            True when the text contains a recognizable email header pattern.
        """
        # This is a fast heuristic rather than a full MIME validation step.
        return bool(InputValidator.MIME_PATTERN.search(content))


def get_input_source(
    has_file: bool,
    filename: str | None,
    file_data: bytes | None,
    raw_text: str,
) -> Tuple[InputMode, str]:
    """Entry point that decides which validation path to use.

    This function acts like a dispatcher. It checks whether the user submitted a
    file upload, raw pasted text, or neither, and then delegates to the correct
    validation method. It also prevents ambiguous requests where both inputs are
    received at the same time.

    In plain English: the app asks, "Did the user send a file or paste text?"
    and then validates exactly one of those inputs before the analysis begins.

    Args:
        has_file: True when a file upload is present.
        filename: The uploaded filename, if any.
        file_data: The uploaded file bytes, if any.
        raw_text: The pasted email text, if any.

    Returns:
        A tuple of the detected input mode and the cleaned content ready for
        later parsing and analysis.

    Raises:
        HTTPException: If both inputs are provided, neither is provided, or the
            selected input fails validation.
    """

    # Determine if the user actually provided any pasted text.
    has_raw_text = raw_text.strip() != ""

    # The app should accept exactly one input source at a time.
    if has_file and has_raw_text:
        raise HTTPException(
            status_code=400,
            detail="Please provide either a file OR raw content, not both. Choose one input method."
        )

    if not has_file and not has_raw_text:
        raise HTTPException(
            status_code=400,
            detail="Please either upload an .eml file or paste raw email content."
        )

    # Route the request to the correct validator.
    if has_file:
        if not file_data:
            raise HTTPException(
                status_code=400,
                detail="File selected but content is empty."
            )
        return InputValidator.validate_file_input(filename, file_data)
    else:
        return InputValidator.validate_raw_content(raw_text)
