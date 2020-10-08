package chatapplication_server.components;
import java.math.BigInteger;
import java.util.*;

public class PrimeHelper
{

    // Returns true if n is prime
    public static boolean isPrime(BigInteger n)
    {
        // Corner cases
        if ( n.compareTo(new BigInteger("1")) == 0 || n.compareTo(new BigInteger("1")) == -1 )
        {
            return false;
        }

        if (n.compareTo(new BigInteger("3")) == 0 || n.compareTo(new BigInteger("3")) == -1)
        {
            return true;
        }

        // This is checked so that we can skip
        // middle five numbers in below loop
        if (n.mod(new BigInteger("2")).equals(0) || n.mod(new BigInteger("3")).equals(0))
        {
            return false;
        }

        BigInteger i = new BigInteger("5");
        for (i = new BigInteger("5"); le(i.pow(2),n); i.add(new BigInteger("6")))
        {
            if (n.mod(i).equals(0) || n.mod(new BigInteger("2").add(i)).equals(0))
            {
                return false;
            }
        }

        return true;
    }

    // Utility function to store prime factors of a number
    public static void findPrimefactors(HashSet<BigInteger> s, BigInteger n)
    {
        // Print the number of 2s that divide n
        while (n.mod(B(2)).equals(0))
        {
            s.add(B(2));
            n = n.divide(B(2));
        }

        // n must be odd at this point. So we can skip
        // one element (Note i = i +2)
        for (BigInteger i = new BigInteger("3"); le(i, n.sqrt()); i = i.add(B(2)))
        {
            // While i divides n, print i and divide n
            while (n.mod(i).equals(0))
            {
                s.add(i);
                n = n.divide(i);
            }
        }

        // This condition is to handle the case when
        // n is a prime number greater than 2
        if (n.compareTo(B(2)) == 1)
        {
            s.add(n);
        }
    }

    // Function to find smallest primitive root of n
    public static BigInteger findPrimitive(BigInteger n)
    {
        HashSet<BigInteger> s = new HashSet<BigInteger>();

        // Check if n is prime or not
        if (isPrime(n) == false)
        {
            return new BigInteger("-1");
        }

        // Find value of Euler Totient function of n
        // Since n is a prime number, the value of Euler
        // Totient function is n-1 as there are n-1
        // relatively prime numbers.
        BigInteger phi = new BigInteger("-1").add(n);

        // Find prime factors of phi and store in a set
        findPrimefactors(s, phi);

        // Check for every number from 2 to phi
        for (BigInteger r = new BigInteger("2"); le(r,phi); r.add(new BigInteger("2")))
        {
            // Iterate through all prime factors of phi.
            // and check if we found a power with value 1
            boolean flag = false;
            for (BigInteger a : s)
            {

                // Check if r^((phi)/primefactors) mod n
                // is 1 or not
                if (r.modPow(phi.divide(a), n).equals(1))
                {
                    flag = true;
                    break;
                }
            }

            // If there was no power with value 1.
            if (flag == false)
            {
                return r;
            }
        }

        // If no primitive root found
        return new BigInteger("-1");
    }

    public static BigInteger B(int i) {
        return new BigInteger(""+i);
    }

    static boolean le(BigInteger a, BigInteger b) {
        return a.compareTo(b) == 0 || a.compareTo(b) == -1;
    }
}

/* This code contributed by PrinciRaj1992 */

