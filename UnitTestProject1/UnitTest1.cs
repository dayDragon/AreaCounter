using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using TriangleArea;

namespace UnitTestProject1
{
    [TestClass]
    public class UnitTest1
    {
        [TestMethod]
        public void TestMethod1()
        {
            try
            {
                Area.Count(-1, 2, 3);
            }
            catch
            {
                return;
            }
            Assert.Fail();
        }

        [TestMethod]
        public void TestMethod2()
        {
            try
            {
                Area.Count(1, -5, 0);
            }
            catch
            {
                return;
            }
            Assert.Fail();
        }

        [TestMethod]
        public void TestMethod3()
        {
            try
            {
                Area.Count(1, 2, 0);
            }
            catch
            {
                return;
            }
            Assert.Fail();
        }

        [TestMethod]
        public void TestMethod4()
        {
            try
            {
                Area.Count(1, 2, 1);
            }
            catch
            {
                return;
            }
            Assert.Fail();
        }

        [TestMethod]
        public void TestMethod5()
        {
            double rez = 0;
            try
            {
                rez = Area.Count(5, 4, 3);
            }
            catch
            {
                Assert.Fail();
            }
            Assert.AreEqual(rez,6);
        }
    }
}
