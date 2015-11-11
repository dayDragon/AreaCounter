using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TriangleArea
{
    public class Area
    {
        public static double Count(double a, double b, double c)
        {
            if(a<=0)
                throw new ArgumentException("a is wrong");
            if(b<=0)
                throw new ArgumentException("b is wrong");
            if(c<=0)
                throw new ArgumentException("c is wrong");

            if (a > b)
            {
                b = a + b;
                a = b - a;
                b = b - a;
            }
            if (b > c)
            {
                c = b + c;
                b = c - b;
                c = c - b;
            }

            if (c * c != a * a + b * b)
                throw new ArgumentException("Triangle is not rectangular");

            return a*b/2;
        }
    }
}
