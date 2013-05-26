/*
 * Created on 12 feb 2010
 */

package craterstudio.util.concur;

import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import craterstudio.util.HighLevel;

public class SimpleBlockingQueue<T>
{
   private static final Object    NULL_VALUE = new Object();

   private final BlockingQueue<T> backing;
   private final int              capacity;

   public SimpleBlockingQueue()
   {
      this(new LinkedBlockingQueue<T>(), Integer.MAX_VALUE);
   }

   public SimpleBlockingQueue(int cap)
   {
      this(new ArrayBlockingQueue<T>(cap), cap);
   }

   private SimpleBlockingQueue(BlockingQueue<T> backing, int capacity)
   {
      this.backing = backing;
      this.capacity = capacity;
   }

   //

   public void clear()
   {
      this.backing.clear();
   }

   public boolean isEmpty()
   {
      return this.backing.isEmpty();
   }

   public int size()
   {
      return this.backing.size();
   }

   public int remaining()
   {
      return this.capacity - this.size();
   }

   public int capacity()
   {
      return this.capacity;
   }

   public void put(T item)
   {
      item = wrap(item);

      try
      {
         for (;;)
         {
            try
            {
               this.backing.put(item);

               break;
            }
            catch (InterruptedException exc)
            {
               continue;
            }
         }
      }
      catch (IllegalMonitorStateException exc)
      {
         // thread was stopped, prevent this 'state' from propagating

         HighLevel.sleep();
      }
   }

   public boolean offer(T item)
   {
      item = wrap(item);

      try
      {
         return this.backing.offer(item);
      }
      catch (IllegalMonitorStateException exc)
      {
         // thread was stopped, prevent this 'state' from propagating 

         HighLevel.sleep();

         return false;
      }
   }

   public boolean offer(T item, long ms)
   {
      item = wrap(item);

      try
      {
         return this.backing.offer(item, ms, TimeUnit.MILLISECONDS);
      }
      catch (InterruptedException exc)
      {
         return false;
      }
      catch (IllegalMonitorStateException exc)
      {
         // thread was stopped, prevent this 'state' from propagating 

         HighLevel.sleep();

         return false;
      }
   }

   public T peek()
   {
      try
      {
         return unwrap(this.backing.peek());
      }
      catch (IllegalMonitorStateException exc)
      {
         // thread was stopped, prevent this 'state' from propagating 

         HighLevel.sleep();

         return null;
      }
   }

   public T peek_inefficient(long ms, boolean yield)
   {
      try
      {
         long deadline = System.nanoTime() + ms * 1000000L;

         while (this.backing.peek() == null && System.nanoTime() <= deadline)
         {
            if (yield)
               Thread.yield();
            else
               HighLevel.sleep(1);
         }

         return this.peek();
      }
      catch (IllegalMonitorStateException exc)
      {
         // thread was stopped, prevent this 'state' from propagating 

         HighLevel.sleep();

         return null;
      }
   }

   public T poll()
   {
      try
      {
         return unwrap(this.backing.poll());
      }
      catch (IllegalMonitorStateException exc)
      {
         // thread was stopped, prevent this 'state' from propagating 

         HighLevel.sleep();

         return null;
      }
   }

   public T poll(long ms)
   {
      try
      {
         return unwrap(this.backing.poll(ms, TimeUnit.MILLISECONDS));
      }
      catch (InterruptedException exc)
      {
         return null;
      }
      catch (IllegalMonitorStateException exc)
      {
         // thread was stopped, prevent this 'state' from propagating 

         HighLevel.sleep();

         return null;
      }
   }

   public T take()
   {
      try
      {
         for (;;)
         {
            try
            {
               return unwrap(this.backing.take());
            }
            catch (InterruptedException exc)
            {
               continue;
            }
         }
      }
      catch (IllegalMonitorStateException exc)
      {
         // thread was stopped, prevent this 'state' from propagating 

         HighLevel.sleep();

         return null;
      }
   }

   T wrap(T item)
   {
      return (item == null) ? (T) NULL_VALUE : item;
   }

   T unwrap(T item)
   {
      return (item == NULL_VALUE) ? null : item;
   }
}