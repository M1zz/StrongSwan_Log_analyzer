

name = "HYUNHO"

def test_a():
    global name
    name = "YUJIN"
    print("a name : ",name)

def test_b():
    print("b name : ",name)

def main():
    print("main name : ",name)
    test_a()
    test_b()
if __name__ == "__main__":
    main()

