path = "tx.txt"
content = ""
with open(path, "r", encoding="utf-8") as file:
    content = file.read()
# print(content)
# read transaction bytes
content = content.stip()
tx_bytes = bytes.fromhex(content)

version = tx_bytes[:4]
version = int.from_bytes(version,'little')
print(version)

