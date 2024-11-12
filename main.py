import struct
import os
import zlib

def try_decode(data, encodings=['utf-8', 'utf-16', 'ascii', 'iso-8859-1']):
    for encoding in encodings:
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return None

def analyze_npk(file_path):
    with open(file_path, 'rb') as f:
        # Read header
        magic = f.read(4)
        if magic != b'NPK\x01':
            print("Invalid NPK file")
            return

        file_count, = struct.unpack('<I', f.read(4))
        print(f"Number of files in package: {file_count}")

        # Read file data
        for i in range(file_count):
            name_length, = struct.unpack('<I', f.read(4))
            file_name = f.read(name_length).decode('utf-8')
            offset, size = struct.unpack('<II', f.read(8))
            print(f"File {i+1}: {file_name}, Size: {size} bytes, Offset: {offset}")

        # Read first file content (example)
        f.seek(offset)
        content = f.read(size)
        print(f"\nFirst 100 bytes of the first file:")
        print(content[:100])

def extract_npk(file_path, output_folder):
    with open(file_path, 'rb') as f:
        magic = f.read(4)
        if magic != b'NPK\x01':
            print("Invalid NPK file")
            return

        file_count, = struct.unpack('<I', f.read(4))
        
        os.makedirs(output_folder, exist_ok=True)

        for i in range(file_count):
            name_length, = struct.unpack('<I', f.read(4))
            file_name = f.read(name_length).decode('utf-8')
            offset, size = struct.unpack('<II', f.read(8))
            
            # อ่านเนื้อหาไฟล์
            current_pos = f.tell()
            f.seek(offset)
            content = f.read(size)
            f.seek(current_pos)
            
            # บันทึกไฟล์
            output_path = os.path.join(output_folder, file_name)
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            with open(output_path, 'wb') as out_file:
                out_file.write(content)
            
            print(f"Extracted file: {file_name}")

def analyze_and_extract_npk(file_path, output_folder):
    with open(file_path, 'rb') as f:
        # Read header
        magic = f.read(4)
        if magic != b'NXPK':
            print("Invalid NPK file")
            return

        num_files, = struct.unpack('<I', f.read(4))
        print(f"Number of files in package: {num_files}")

        f.seek(12, 1)  # Skip 12 bytes

        index_offset, = struct.unpack('<I', f.read(4))
        print(f"File index position: {index_offset}")

        # ไปยังตำแหน่งดัชนีไฟล์
        f.seek(index_offset)

        file_info = []
        for _ in range(num_files):
            f.seek(4, 1)  # ข้าม 4 ไบต์แรก
            address, comp_size, uncomp_size, zcrc, crc = struct.unpack('<IIIII', f.read(20))
            zip_flag, decrypt_flag = struct.unpack('<HH', f.read(4))
            file_info.append((address, comp_size, uncomp_size, zcrc, crc, zip_flag, decrypt_flag))

        # อ่านรายชื่อไฟล์
        file_list_offset = index_offset + (num_files * 28) + 16
        f.seek(file_list_offset)
        file_names = f.read().decode('utf-8').split('\x00')
        file_names = [name for name in file_names if name]  # ลบชื่อไฟล์ว่าง

        # สร้างโฟลเดอร์เอาต์พุต
        os.makedirs(output_folder, exist_ok=True)

        # แยกไฟล์
        for (address, comp_size, uncomp_size, zcrc, crc, zip_flag, decrypt_flag), file_name in zip(file_info, file_names):
            print(f"Extracting file: {file_name}")
            print(f"  Compressed size: {comp_size}, Uncompressed size: {uncomp_size}")
            print(f"  ZCRC: {zcrc:08X}, CRC: {crc:08X}")
            print(f"  ZIP Flag: {zip_flag}, Decrypt Flag: {decrypt_flag}")

            f.seek(address)
            data = f.read(comp_size)

            if zip_flag == 2:
                try:
                    data = zlib.decompress(data)
                except zlib.error:
                    print(f"  Failed to decompress file: {file_name}")
                    continue

            output_path = os.path.join(output_folder, file_name)
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            with open(output_path, 'wb') as out_file:
                out_file.write(data)

            print(f"  Saved to: {output_path}")
            print()

if __name__ == "__main__":
    npk_file = "h.npk"  # ชื่อไฟล์ .NPK ของคุณ
    output_folder = "extracted_files"
    analyze_and_extract_npk(npk_file, output_folder)
