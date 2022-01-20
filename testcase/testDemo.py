import pytest
class Test_01:

    def test_001(self):
        print('Test_01下的用例001')
        assert  1 == 1

    def test_002(self):
        print('Test_01下的用例002')
        assert  1 == 2

    def test_003(self):
        print('Test_01下的用例003')
        assert 3 == 3

if __name__ == '__main__':
    pytest.main(['-s'])