import unittest
from phishcheck import analyze

class TestPhishcheck(unittest.TestCase):
    def test_clean_domain(self):
        r = analyze("https://www.google.com")
        self.assertEqual(r["verdict"], "low risk")
        self.assertLess(r["score"], 25)

    def test_ip_host(self):
        r = analyze("http://192.168.1.1/login")
        self.assertTrue(any("raw IP" in w for _, w in r["findings"]))

    def test_at_trick(self):
        r = analyze("http://google.com@evil.example.com/")
        self.assertTrue(any("@" in w for _, w in r["findings"]))
        self.assertGreaterEqual(r["score"], 25)

    def test_punycode(self):
        r = analyze("https://xn--pple-43d.com/")
        self.assertTrue(any("punycode" in w for _, w in r["findings"]))

    def test_shortener(self):
        r = analyze("https://bit.ly/3xAbCdE")
        self.assertTrue(any("shortener" in w for _, w in r["findings"]))

    def test_brand_lookalike(self):
        r = analyze("https://paypal-secure-login.example.tk/")
        self.assertEqual(r["verdict"], "high risk")

    def test_risky_tld_and_keywords(self):
        r = analyze("http://verify-account-update.tk/login")
        self.assertGreaterEqual(r["score"], 40)

    def test_unparseable_is_high(self):
        r = analyze(":::")
        self.assertEqual(r["verdict"], "high risk")

    def test_subdomain_chain(self):
        r = analyze("https://a.b.c.d.example.com/")
        self.assertTrue(any("subdomains" in w for _, w in r["findings"]))

    def test_score_capped(self):
        r = analyze("http://xn--a@10.0.0.1:8080/" + "login-" * 10 + ".tk")
        self.assertLessEqual(r["score"], 100)

if __name__ == "__main__":
    unittest.main()
