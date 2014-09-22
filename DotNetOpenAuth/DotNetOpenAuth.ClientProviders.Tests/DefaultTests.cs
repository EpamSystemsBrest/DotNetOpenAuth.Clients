using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using ClientProviders;

namespace DotNetOpenAuth.ClientProviders.Tests {
    [TestClass]
    public class DefaultTests {
        [TestMethod]
        public void TestAddToReturnRightValue() {
            Assert.AreEqual(Default.Add(5, 3), 8);
        }

        [TestMethod]
        public void TestAddToReturnWrongValue() {
            Assert.AreNotEqual(Default.Add(5, 3), 9);
        }
    }
}
