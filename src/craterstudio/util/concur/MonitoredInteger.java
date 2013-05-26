/*
 * Created on Nov 16, 2008
 */

package craterstudio.util.concur;

import craterstudio.util.HighLevel;

public class MonitoredInteger
{
   private int          value;
   private final Object lock;

   public MonitoredInteger()
   {
      this.value = 0;
      this.lock = new Object();
   }

   //

   public void set(int value)
   {
      synchronized (this.lock)
      {
         this.value = value;

         this.lock.notifyAll();
      }
   }

   public int get()
   {
      synchronized (this.lock)
      {
         return this.value;
      }
   }

   public int adjust(int amount)
   {
      synchronized (this.lock)
      {
         this.value += amount;

         this.lock.notifyAll();
         
         return this.value;
      }
   }

   //

   public int waitForModification()
   {
      synchronized (this.lock)
      {
         int valueAtStart = this.value;

         while (this.value != valueAtStart)
         {
            HighLevel.wait(this.lock);
         }

         return this.value;
      }
   }

   public void waitForEqual(int value)
   {
      synchronized (this.lock)
      {
         while (this.value != value)
         {
            HighLevel.wait(this.lock);
         }
      }
   }

   public void waitForNotEqual(int value)
   {
      synchronized (this.lock)
      {
         while (this.value == value)
         {
            HighLevel.wait(this.lock);
         }
      }
   }

   public int waitForLessThan(int value)
   {
      synchronized (this.lock)
      {
         while (this.value >= value)
         {
            HighLevel.wait(this.lock);
         }

         return this.value;
      }
   }

   public int waitForGreaterThan(int value)
   {
      synchronized (this.lock)
      {
         while (this.value <= value)
         {
            HighLevel.wait(this.lock);
         }

         return this.value;
      }
   }

   //

   public int waitForEqualAndAdjust(int equal, int adjust)
   {
      synchronized (this.lock)
      {
         this.waitForEqual(equal);
         this.adjust(adjust);
         return this.value;
      }
   }

   public int waitForNotEqualAndAdjust(int notEqual, int adjust)
   {
      synchronized (this.lock)
      {
         this.waitForNotEqual(notEqual);
         this.adjust(adjust);
         return this.value;
      }
   }

   public int waitForLessThanAndAdjust(int lessThan, int adjust)
   {
      synchronized (this.lock)
      {
         this.waitForLessThan(lessThan);
         this.adjust(adjust);
         return this.value;
      }
   }

   public int waitForGreaterThanAndAdjust(int greaterThan, int adjust)
   {
      synchronized (this.lock)
      {
         this.waitForGreaterThan(greaterThan);
         this.adjust(adjust);
         return this.value;
      }
   }

   //

   public int waitForEqualAndSet(int equal, int set)
   {
      synchronized (this.lock)
      {
         this.waitForEqual(equal);
         this.set(set);
         return this.value;
      }
   }

   public int waitForNotEqualAndSet(int notEqual, int set)
   {
      synchronized (this.lock)
      {
         this.waitForNotEqual(notEqual);
         this.set(set);
         return this.value;
      }
   }

   public int waitForLessThanAndSet(int lessThan, int set)
   {
      synchronized (this.lock)
      {
         this.waitForLessThan(lessThan);
         this.set(set);
         return this.value;
      }
   }

   public int waitForGreaterThanAndSet(int greaterThan, int set)
   {
      synchronized (this.lock)
      {
         this.waitForGreaterThan(greaterThan);
         this.set(set);
         return this.value;
      }
   }
}