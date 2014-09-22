using Clients;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace DotNetOpenAuth.Clients.Tests {
    [TestClass]
    public class DefaultTests {
        [TestMethod]
        public void TestAddToReturnRightValue() {
            Assert.AreEqual(Default.Add(5, 3), 8);
        }

        [TestMethod]
        public void TestAddToReturnWrongValue() {
            Assert.AreNotEqual(Default.Add(5, 3), 1);
        }
    }
}
