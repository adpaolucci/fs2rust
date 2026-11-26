#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NtStatusInfo {
    pub code: u32,
    pub hex: String,
    pub name: &'static str,
    pub description: &'static str,
    pub severity: &'static str,
}

impl NtStatusInfo {
    pub fn is_success(&self) -> bool {
        self.code == 0
    }

    pub fn is_informational(&self) -> bool {
        (self.code >> 30) == 1 || self.code == 0x0000_0103
    }

    pub fn is_warning(&self) -> bool {
        (self.code >> 30) == 2
    }

    pub fn is_error(&self) -> bool {
        (self.code >> 30) == 3
    }
}

pub fn decode_ntstatus(code: u32) -> NtStatusInfo {
    let (name, description) = match code {
        0x0000_0000 => ("STATUS_SUCCESS", "The operation completed successfully"),
        0x0000_0103 => ("STATUS_PENDING", "The operation is pending completion"),
        0x0000_0104 => ("STATUS_REPARSE", "A reparse should be performed by the Object Manager"),
        0x0000_010C => ("STATUS_NOTIFY_ENUM_DIR", "Directory notification buffer overflowed"),
        0x8000_0005 => (
            "STATUS_BUFFER_OVERFLOW",
            "Data was too large to fit into the specified buffer",
        ),
        0x8000_0006 => (
            "STATUS_NO_MORE_FILES",
            "No more files were found matching the specification",
        ),
        0x8000_001A => (
            "STATUS_NO_MORE_ENTRIES",
            "No more entries are available from an enumeration",
        ),
        0xC000_0001 => ("STATUS_UNSUCCESSFUL", "The requested operation was unsuccessful"),
        0xC000_0002 => ("STATUS_NOT_IMPLEMENTED", "The requested operation is not implemented"),
        0xC000_0005 => ("STATUS_ACCESS_VIOLATION", "Invalid memory access occurred"),
        0xC000_0008 => ("STATUS_INVALID_HANDLE", "An invalid handle was specified"),
        0xC000_000D => (
            "STATUS_INVALID_PARAMETER",
            "An invalid parameter was passed to a service or function",
        ),
        0xC000_000E => ("STATUS_NO_SUCH_DEVICE", "A device which does not exist was specified"),
        0xC000_000F => ("STATUS_NO_SUCH_FILE", "The file does not exist"),
        0xC000_0010 => (
            "STATUS_INVALID_DEVICE_REQUEST",
            "The specified request is not a valid operation for the target device",
        ),
        0xC000_0011 => ("STATUS_END_OF_FILE", "The end-of-file marker has been reached"),
        0xC000_0013 => ("STATUS_NO_MEDIA_IN_DEVICE", "There is no media in the drive"),
        0xC000_0022 => (
            "STATUS_ACCESS_DENIED",
            "A process has requested access to an object but has not been granted those access rights",
        ),
        0xC000_0023 => (
            "STATUS_BUFFER_TOO_SMALL",
            "The buffer is too small to contain the entry",
        ),
        0xC000_0033 => ("STATUS_OBJECT_NAME_INVALID", "The object name is invalid"),
        0xC000_0034 => ("STATUS_OBJECT_NAME_NOT_FOUND", "The object name is not found"),
        0xC000_0035 => ("STATUS_OBJECT_NAME_COLLISION", "The object name already exists"),
        0xC000_003A => ("STATUS_OBJECT_PATH_NOT_FOUND", "The path does not exist"),
        0xC000_003B => (
            "STATUS_OBJECT_PATH_SYNTAX_BAD",
            "The object path component was not a directory object or syntax was invalid",
        ),
        0xC000_0043 => (
            "STATUS_SHARING_VIOLATION",
            "A file cannot be opened because the share access flags are incompatible",
        ),
        0xC000_0054 => (
            "STATUS_FILE_LOCK_CONFLICT",
            "A requested read/write cannot be granted due to a range lock conflict",
        ),
        0xC000_0055 => (
            "STATUS_LOCK_NOT_GRANTED",
            "A requested file lock could not be granted due to other locks",
        ),
        0xC000_0056 => (
            "STATUS_DELETE_PENDING",
            "A non-close operation has been requested on a file object with a delete pending",
        ),
        0xC000_0061 => (
            "STATUS_PRIVILEGE_NOT_HELD",
            "A required privilege is not held by the client",
        ),
        0xC000_007F => ("STATUS_DISK_FULL", "There is not enough space on the disk"),
        0xC000_00A2 => ("STATUS_MEDIA_WRITE_PROTECTED", "The media is write protected"),
        0xC000_00BA => (
            "STATUS_FILE_IS_A_DIRECTORY",
            "The file specified is a directory and cannot be opened as a regular file",
        ),
        0xC000_00BB => ("STATUS_NOT_SUPPORTED", "The request is not supported"),
        0xC000_0101 => (
            "STATUS_DIRECTORY_NOT_EMPTY",
            "Indicates a directory that was tried to be deleted is not empty",
        ),
        0xC000_0102 => (
            "STATUS_FILE_CORRUPT_ERROR",
            "The file or directory is corrupted and unreadable",
        ),
        0xC000_0103 => ("STATUS_NOT_A_DIRECTORY", "A requested opened file is not a directory"),
        0xC000_0120 => ("STATUS_CANCELLED", "The I/O request was canceled"),
        0xC000_0121 => (
            "STATUS_CANNOT_DELETE",
            "An attempt was made to delete a file that cannot be deleted",
        ),
        0xC000_0225 => ("STATUS_NOT_FOUND", "The object was not found"),
        0xC000_0275 => (
            "STATUS_NOT_A_REPARSE_POINT",
            "The file or directory is not a reparse point",
        ),
        _ => ("STATUS_UNKNOWN", "Unrecognized NTSTATUS code"),
    };
    let severity = match code >> 30 {
        0 => "Success",
        1 => "Informational",
        2 => "Warning",
        _ => "Error",
    };
    NtStatusInfo {
        code,
        hex: format!("0x{code:08X}"),
        name,
        description,
        severity,
    }
}
