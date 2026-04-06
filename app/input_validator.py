# app/input_validator.py

"""
Input validation and sanitization for email content.
Handles both file uploads and raw text input with security measures.
"""

from enum import Enum
from typing import Tuple
import re
from fastapi import HTTPException


class InputMode(str, Enum):
    """Enum for input source type."""
    FILE_UPLOAD = "file"
    RAW_CONTENT = "raw"


class InputValidator:
    """Validates and sanitizes email input from different sources."""
    
    # Regex pattern for basic MIME structure detection
    MIME_PATTERN = re.compile(
        r'^(From:|To:|Subject:|Date:|Message-ID:|MIME-Version:|Content-Type:)',
        re.MULTILINE
    )
    
    # Max sizes
    MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB
    MAX_RAW_TEXT_SIZE = 100 * 1024 * 1024  # 100MB
    
    @staticmethod
    def validate_file_input(filename: str | None, data: bytes) -> Tuple[str, str]:
        """
        Validate file upload.
        
        Args:
            filename: The uploaded file name
            data: Raw file content bytes
            
        Returns:
            Tuple of (InputMode.FILE_UPLOAD, decoded_content)
            
        Raises:
            HTTPException: If validation fails
        """
        # Check if filename exists and is valid
        if not filename:
            raise HTTPException(
                status_code=400,
                detail="File name missing. Please select a valid .eml file."
            )
        
        # Validate extension
        if not filename.lower().endswith('.eml'):
            raise HTTPException(
                status_code=400,
                detail=f"Invalid file extension. Only .eml files are allowed. Got: {filename.split('.')[-1]}"
            )
        
        # Check file size
        if len(data) > InputValidator.MAX_FILE_SIZE:
            raise HTTPException(
                status_code=413,
                detail=f"File too large. Maximum size is {InputValidator.MAX_FILE_SIZE / 1024 / 1024:.1f}MB"
            )
        
        # Check for empty files
        if len(data) == 0:
            raise HTTPException(
                status_code=400,
                detail="Uploaded file is empty."
            )
        
        # Decode content with fallback encoding
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
        """
        Validate raw email content with security checks.
        
        Args:
            content: Raw email text content
            
        Returns:
            Tuple of (InputMode.RAW_CONTENT, validated_sanitized_content)
            
        Raises:
            HTTPException: If validation fails
        """
        # Strip whitespace
        content = content.strip()
        
        # Check for empty content
        if not content:
            raise HTTPException(
                status_code=400,
                detail="Please paste email content. Text area is empty."
            )
        
        # Check size limit
        if len(content) > InputValidator.MAX_RAW_TEXT_SIZE:
            raise HTTPException(
                status_code=413,
                detail=f"Content too large. Maximum size is {InputValidator.MAX_RAW_TEXT_SIZE / 1024 / 1024:.1f}MB"
            )
        
        # Sanitize for script injection (but preserve email headers/body)
        sanitized = InputValidator._sanitize_content(content)
        
        # Basic validation that it looks like email content
        if not InputValidator._looks_like_email(sanitized):
            raise HTTPException(
                status_code=400,
                detail="Content doesn't appear to be valid email format. "
                       "Expected standard email headers (From:, To:, Subject:, etc.)"
            )
        
        return InputMode.RAW_CONTENT, sanitized
    
    @staticmethod
    def _sanitize_content(content: str) -> str:
        """
        Sanitize raw email content against common injection attacks.
        
        Preserves email structure while removing potentially dangerous patterns.
        """
        lines = content.split('\n')
        cleaned_lines = []
        
        for line in lines:
            # Remove control characters except standard whitespace
            # This prevents null byte injection and other control char exploits
            clean_line = ''.join(
                char for char in line
                if ord(char) >= 32 or char in '\t'
            )
            cleaned_lines.append(clean_line)
        
        return '\n'.join(cleaned_lines)
    
    @staticmethod
    def _looks_like_email(content: str) -> bool:
        """
        Perform basic heuristic check that content looks like email.
        
        Returns True if content has typical email headers.
        """
        # Check for at least one common email header
        return bool(InputValidator.MIME_PATTERN.search(content))


def get_input_source(
    has_file: bool,
    filename: str | None,
    file_data: bytes | None,
    raw_text: str,
) -> Tuple[InputMode, str]:
    """
    Determine input source and validate accordingly.
    
    This is the main entry point for input validation.
    
    Args:
        has_file: Whether a file was actually uploaded
        filename: File name if provided
        file_data: File bytes if provided
        raw_text: Raw text content if provided
        
    Returns:
        Tuple of (InputMode, validated_content)
        
    Raises:
        HTTPException: If both or neither input is provided, or validation fails
    """
    
    # Determine which input was provided
    has_raw_text = raw_text.strip() != ""
    
    # Reject if both or neither provided
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
    
    # Process based on which was provided
    if has_file:
        if not file_data:
            raise HTTPException(
                status_code=400,
                detail="File selected but content is empty."
            )
        return InputValidator.validate_file_input(filename, file_data)
    else:
        return InputValidator.validate_raw_content(raw_text)
