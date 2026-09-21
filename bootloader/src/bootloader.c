#include "bootloader.h"

// clang-format off
#include "ch.h"
#include "hal.h"
// clang-format on

#include <chscanf.h>
#include <id_eeprom.h>
#include <sha256.h>
#include <stdlib.h>
#include <stm32h7xx_hal.h>

#include "board_ex.h"
#include "chprintf.h"
#include "globals.h"
#include "lwip/sockets.h"

// Macro to send a constant string to a socket
#define SEND(sock, str) write(sock, str, strlen(str))

#define GREETING_MESSAGE "BOOTLOADER VERSION:xcore-boot v1.1"
#define BOARD_MSG "BOARD:"
#define VERSION_MSG "HARDWARE VERSION:"
#define CARRIER_BOARD_MSG "CARRIER BOARD:"
#define CARRIER_BOARD_VERSION_MSG "CARRIER BOARD VERSION:"
#define BOOTLOADER_PORT 8007

// 256bits need to be written at a single time and the buffer needs to be
// aligned, so we first copy our bytes into this tmp buffer and then let the
// hardware write to flash.
static uint8_t buffer[1000] __attribute__((aligned(32))) = {};

// Buffer for sending responses
static char out_buffer[1000];

// Working Area for the bootloader thread
static THD_WORKING_AREA(wa_bootloader_thread, 128000);

enum BOOTLOADER_STATE { HASH, IMAGE_SIZE, IMAGE_DATA };

static SHA256_CTX sha256;

/**
 * Parses a SHA-256 hash in hexadecimal format from the given buffer.
 *
 * @param buf  Pointer to the input buffer containing the hash in hexadecimal
 * format.
 * @param buflen  Length of the input buffer. Must be 64 to be valid.
 * @param hash  Array of 8 uint32_t elements to store the parsed hash.
 * @return true if the hash was successfully parsed, false otherwise.
 */
static bool parseSHA256(const char *buf, size_t buflen, uint8_t hash[32]) {
  if (buflen != 64) {
    return false;
  }
  for (uint8_t i = 0; i < 32; i++) {
    hash[i] = 0;
    for (uint8_t j = 0; j < 2; j++) {
      // 4 bits per character
      hash[i] <<= 4;
      char c = buf[2 * i + j];
      if (c >= '0' && c <= '9') {
        hash[i] |= c - '0';
      } else if (c >= 'A' && c <= 'F') {
        hash[i] |= (c - 'A') + 10;
      } else if (c >= 'a' && c <= 'f') {
        hash[i] |= (c - 'a') + 10;
      } else {
        return false;
      }
    }
  }
  return true;
}

static int ReadLine(int connfd) {
  // reset first byte in case of timeout with 0 bytes received
  buffer[0] = 0;
  size_t buffer_fill = 0;
  size_t bytes_received = 0;
  do {
    bytes_received = read(connfd, buffer + buffer_fill, 1);
    buffer_fill += bytes_received;
  } while (bytes_received > 0 && buffer[buffer_fill - 1] != '\n' &&
           buffer_fill < sizeof(buffer));

  // Nothing received
  if (buffer_fill == 0) return -1;

  // Check, if it's actually a line
  if (buffer[buffer_fill - 1] != '\n') return -1;

  // Check for empty string (i.e. "\n")
  if (buffer_fill == 1) return 0;

  // Here, buffer has at least 2 bytes and we have \n, so there's two cases:
  // Either we have \r\n as line ending, or it's \n
  if (buffer[buffer_fill - 2] == '\r') {
    buffer[buffer_fill - 2] = 0;
    return (int)buffer_fill - 2;
  }

  buffer[buffer_fill - 1] = 0;
  return (int)buffer_fill - 1;
}

static bool HandleUpload(int connfd) {
  SEND(connfd, "SEND HASH\n");

  enum BOOTLOADER_STATE state = HASH;

  FLASH_EraseInitTypeDef EraseInitStruct;

  // Handle the connection
  int bytes_received;
  size_t buffer_fill = 0;
  size_t receive_bytes = 1;
  uint8_t hash[32];
  bool ok = true;

  size_t image_size = 0;
  size_t received_bytes = 0;

  // State for flashing
  uint32_t flash_address = TARGET_FLASH_ADDRESS;

  while (ok && buffer_fill < (sizeof(buffer) - receive_bytes) &&
         (bytes_received = read(connfd, buffer + buffer_fill, receive_bytes)) >
             0) {
    buffer_fill += bytes_received;

    switch (state) {
      case HASH:
        // Receive single bytes until we have 64
        receive_bytes = 1;
        if (buffer[buffer_fill - 1] != '\n') {
          continue;
        }
        if (buffer_fill < 64) {
          ok = false;
          continue;
        }

        bool hash_ok = parseSHA256((const char *)buffer, 64, hash);
        if (!hash_ok) {
          ok = false;
          continue;
        }

        SEND(connfd, "HASH OK\nSEND LENGTH\n");
        buffer_fill = 0;
        state = IMAGE_SIZE;
        break;
      case IMAGE_SIZE: {
        receive_bytes = 1;
        if (buffer[buffer_fill - 1] != '\n') {
          continue;
        }
        // Put 0 termination
        buffer[buffer_fill - 1] = 0;
        image_size = strtol((const char *)buffer, NULL, 10);
        chsnprintf(out_buffer, sizeof(out_buffer), ">Image size: %u\n",
                   image_size);
        write(connfd, out_buffer, strlen(out_buffer));

        if (image_size > PROGRAM_FLASH_SIZE_BYTES) {
          SEND(connfd, "ILLEGAL SIZE");
          ok = false;
          continue;
        }

#if BOARD_HAS_EEPROM
        struct bootloader_info info;
        ID_EEPROM_GetBootloaderInfo(&info);
        info.image_present = false;
        memset(info.image_sha256, 0, sizeof(info.image_sha256));
        if (!ID_EEPROM_SaveBootloaderInfo(&info)) {
          SEND(connfd, ">Error clearing EEPROM");
          ok = false;
          continue;
        }
#endif

        EraseInitStruct.NbSectors =
            (image_size + FLASH_PAGE_SIZE_BYTES - 1) / FLASH_PAGE_SIZE_BYTES;
        chsnprintf(out_buffer, sizeof(out_buffer), ">Erasing %u Flash Pages.\n",
                   EraseInitStruct.NbSectors);
        write(connfd, out_buffer, strlen(out_buffer));

        SEND(connfd, "LENGTH OK\n");
        HAL_FLASH_Unlock();
        SEND(connfd, ">Erasing Chip...\n");
        EraseInitStruct.TypeErase = FLASH_TYPEERASE_SECTORS;
        EraseInitStruct.VoltageRange = FLASH_VOLTAGE_RANGE_3;
        EraseInitStruct.Banks = FLASH_BANK_1;
        EraseInitStruct.Sector = FLASH_SECTOR_1;

        uint32_t e = 0;
        ok &= HAL_FLASHEx_Erase(&EraseInitStruct, &e) == HAL_OK;
        if (!ok) {
          SEND(connfd, ">Error during Erase\n");
          continue;
        }

        SEND(connfd, ">Erasing Done\n");

        SEND(connfd, "SEND DATA\n");
        buffer_fill = 0;
        received_bytes = 0;
        sha256_init(&sha256);
        state = IMAGE_DATA;
      } break;
      case IMAGE_DATA:
        // Read 32 bytes at a time (except for when the buffer ends)
        if (buffer_fill < 32 && (buffer_fill + received_bytes) != image_size) {
          continue;
        }
        received_bytes += buffer_fill;
        sha256_update(&sha256, buffer, buffer_fill);
        // zeropad, if we're in the last block of data
        while (buffer_fill < 32) {
          buffer[buffer_fill++] = 0;
        }

        if (HAL_FLASH_Program(FLASH_TYPEPROGRAM_FLASHWORD, flash_address,
                              (uint32_t)(&buffer)) != HAL_OK) {
          SEND(connfd, ">Flash Program Error!\n");
          ok = false;
          continue;
        }
        flash_address += 32;
        buffer_fill = 0;
        if (received_bytes == image_size) {
          // done, break out
          break;
        }
        break;
      default:
        break;
    }
  }

  // Verify image
  if (ok) {
    HAL_FLASH_Lock();

    SEND(connfd, ">Verifying Hash");
    uint8_t validate_hash[32];
    memset(validate_hash, 0, sizeof(validate_hash));
    // This verifies the received bytes
    sha256_final(&sha256, validate_hash);
    if (memcmp(validate_hash, hash, sizeof(hash)) == 0) {
      SEND(connfd, ">Receive Verify OK\n");
    } else {
      SEND(connfd, ">Receive Verify Failed\n");
      ok = false;
    }
  }

  if (ok) {
    uint8_t validate_hash[32];
    // Now verify the actual written bytes
    sha256_init(&sha256);
    memset(validate_hash, 0, sizeof(validate_hash));
    sha256_update(&sha256, (uint8_t *)TARGET_FLASH_ADDRESS, image_size);
    sha256_final(&sha256, validate_hash);
    if (memcmp(validate_hash, hash, sizeof(hash)) == 0) {
      SEND(connfd, ">Flash Verify OK\n");
    } else {
      SEND(connfd, ">Flash Verify Failed\n");
      ok = false;
    }
  }

#if BOARD_HAS_EEPROM
  if (ok) {
    // Store bootloader info
    struct bootloader_info info;
    ID_EEPROM_GetBootloaderInfo(&info);
    info.image_present = 1;
    info.image_size = image_size;
    memcpy(info.image_sha256, hash, sizeof(hash));
    if (!ID_EEPROM_SaveBootloaderInfo(&info)) {
      SEND(connfd, ">Error storing EEPROM");
      ok = false;
      return false;
    }
  }
#endif

  return ok;
}

static bool GetDevMode(int connfd) {
  struct bootloader_info info;
  // Read current value
  ID_EEPROM_GetBootloaderInfo(&info);
  if (info.developer_mode == 1) {
    SEND(connfd, "Enabled\n");
  } else {
    SEND(connfd, "Disabled\n");
  }
  return true;
}

static bool SetDevMode(int connfd) {
  SEND(connfd, "SEND DEV_MODE_ENABLED\n");
  int length = ReadLine(connfd);
  if (length != 1) {
    SEND(connfd, "ERROR\n");
    return false;
  }
  bool value;
  switch (buffer[0]) {
    case '0':
      SEND(connfd, "> Dev Mode: Disabled.\n");
      value = false;
      break;
    case '1':
      SEND(connfd, "> Dev Mode: Enabled.\n");
      value = true;
      break;
    default:
      SEND(connfd, "> Error: Illegal value. Send either 1 or 0\n");
      return false;
  }

  // Store bootloader info
  struct bootloader_info info;
  // Read current value
  ID_EEPROM_GetBootloaderInfo(&info);
  // Overwrite developer mode and store
  info.developer_mode = value;
  if (!ID_EEPROM_SaveBootloaderInfo(&info)) {
    SEND(connfd, ">Error storing EEPROM\n");
    return false;
  }
  SEND(connfd, ">Successfully updated EEPROM\n");
  return true;
}

static THD_FUNCTION(bootloader_thread, arg) {
  (void)arg;
  chRegSetThreadName("Bootloader");

  // Create a socket
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) {
    return;
  }

  // Bind the socket to a port
  struct sockaddr_in server_addr;
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  server_addr.sin_port = htons(BOOTLOADER_PORT);

  if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
    lwip_close(sockfd);
    return;
  }

  // Listen for incoming connections
  if (listen(sockfd, 0) < 0) {
    lwip_close(sockfd);
    return;
  }

  bool locked = false;

  // Main loop
  while (1) {
    // Accept a new connection
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    int connfd = accept(sockfd, (struct sockaddr *)&client_addr, &client_len);
    if (connfd < 0) {
      continue;
    }

    // Prevent chip from starting while bootloading
    if (!locked) {
      chMtxLock(&reboot_mutex);
      locked = true;
    }

    int flag = 1;
    int result =
        setsockopt(connfd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
    if (result < 0) {
      close(connfd);
      continue;
    }
    // Write Hardware Info
    SEND(connfd, GREETING_MESSAGE);
    SEND(connfd, "\n");
    SEND(connfd, BOARD_MSG);
    write(connfd, board_info.board_id,
          strnlen(board_info.board_id, sizeof(board_info.board_id)));
    SEND(connfd, "\n");
    SEND(connfd, VERSION_MSG);
    char version_buffer[50] = {0};
    chsnprintf(version_buffer, sizeof(version_buffer), "%d.%d.%d\n",
               board_info.version_major, board_info.version_minor,
               board_info.version_patch);
    SEND(connfd, version_buffer);
    SEND(connfd, CARRIER_BOARD_MSG);
    write(connfd, carrier_board_info.board_id,
          strnlen(carrier_board_info.board_id,
                  sizeof(carrier_board_info.board_id)));
    SEND(connfd, "\n");
    SEND(connfd, CARRIER_BOARD_VERSION_MSG);
    chsnprintf(version_buffer, sizeof(version_buffer), "%d.%d.%d\n",
               carrier_board_info.version_major,
               carrier_board_info.version_minor,
               carrier_board_info.version_patch);
    SEND(connfd, version_buffer);

    SEND(connfd, "SEND COMMAND\n");

    int command_len = ReadLine(connfd);
    if (command_len < 0) {
      SEND(connfd, "> ERROR reading command\n");
    } else {
      SEND(connfd, "> Got command: ");
      SEND(connfd, buffer);
      SEND(connfd, "\n");

      if (strncmp("UPLOAD", buffer, command_len) == 0) {
        // Start Upload
        HandleUpload(connfd);
      } else if (strncmp("SET_DEV_MODE", buffer, command_len) == 0) {
        SetDevMode(connfd);
      } else if (strncmp("GET_DEV_MODE", buffer, command_len) == 0) {
        GetDevMode(connfd);
      } else if (strcmp("BOOT", (const char *)buffer) == 0) {
        // The command thread already owns reboot_mutex, so no upload can
        // overlap this request. Keep the same image/developer-mode checks
        // as the normal timed boot path; only skip its waiting period.
        SEND(connfd, "BOOT REQUESTED\n");
        chThdSleep(TIME_MS2I(100));
        jump_to_user_program();
        // A valid application never returns from jump_to_user_program().
        SEND(connfd, "BOOT FAILED\n");
      } else {
        SEND(connfd, "> Unknown Command\n");
      }
    }

    // Sleep to allow TCP thread to send some data before closing the socket
    chThdSleep(TIME_MS2I(100));

    close(connfd);

    // Allow reboot into user program
    locked = false;
    chMtxUnlock(&reboot_mutex);
  }
}

void InitBootloaderThread() {
  chThdCreateStatic(wa_bootloader_thread, sizeof(wa_bootloader_thread),
                    NORMALPRIO + 0, bootloader_thread, NULL);
}
