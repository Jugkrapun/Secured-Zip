Project Comsecurity - Secured Zip
Group member
    1. ID: 6688229  Name: Jugkrapun Withyakonkomon
    2.

!!What we need to do now
The encryption and decryption function must be performed automatically once saving or opening a compressed/uncompressed file.

หมายถึงระบบหรือโปรแกรมของคุณ ไม่ต้องให้ผู้ใช้กดปุ่มเข้ารหัสหรือถอดรหัสเอง —
แต่ให้มัน ทำงานให้อัตโนมัติ ในสองจังหวะนี้:

เมื่อผู้ใช้บันทึกไฟล์ ZIP (หรือบีบอัดไฟล์)
→ โปรแกรมต้อง “เข้ารหัส” (encrypt) ให้ทันทีโดยอัตโนมัติ
เช่น เมื่อ zip เสร็จ → ระบบเรียก encrypt_file_aes() เอง

เมื่อผู้ใช้เปิดไฟล์ ZIP ที่บีบอัดไว้ (หรือแตกไฟล์).
→ โปรแกรมต้อง “ถอดรหัส” (decrypt) ให้ก่อนอัตโนมัติ
เช่น ก่อน unzip → ระบบเรียก decrypt_file_aes() เอง