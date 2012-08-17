/*
 * Created on 7 mrt 2011
 */

package craterstudio.math;

import java.util.Arrays;

public class PrimeNumbers
{
   private static int[] HUNDRED_PRIMES = new int[100];

   public static int[] hundredPrimes()
   {
      return HUNDRED_PRIMES.clone();
   }

   static
   {
      PrimeNumbers obj = new PrimeNumbers();
      for (int i = 0; i < HUNDRED_PRIMES.length; i++)
         HUNDRED_PRIMES[i] = obj.next();
   }

   public static int getNthPrime(int n)
   {
      return HUNDRED_PRIMES[n];
   }

   private int[] primes;
   private int   len;

   public PrimeNumbers()
   {
      this.primes = new int[16];
      this.len = 0;
   }

   public int size()
   {
      return this.len;
   }

   public int get(int i)
   {
      while (this.size() <= i)
         this.next();
      return this.primes[i];
   }

   public int next()
   {
      if (this.len == 0)
      {
         this.primes[this.len++] = 2;
         return 2;
      }

      int last = this.primes[this.len - 1];
      int test = last;

      outer: while (true)
      {
         test += 1;

         for (int i = 0; i < this.len; i++)
            if (test % this.primes[i] == 0)
               continue outer;

         if (this.primes.length == this.len)
            this.primes = Arrays.copyOf(this.primes, this.primes.length * 2);

         this.primes[this.len++] = test;
         return test;
      }
   }
}
