/*
 * Created on 10-apr-2007
 */

package craterstudio.util.concur;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

import craterstudio.util.HighLevel;

public class ConcurrentQueue<T>
{
   private final LinkedList<T> queue;
   private final Object        mutex;
   private final boolean       doNotifyAll;

   public ConcurrentQueue(boolean doNotifyAll)
   {
      this.queue = new LinkedList<T>();
      this.mutex = new Object();
      this.doNotifyAll = doNotifyAll;
   }

   public final boolean isEmpty()
   {
      return this.size() == 0;
   }

   public final void waitForEmpty()
   {
      synchronized (mutex)
      {
         while (!queue.isEmpty())
         {
            HighLevel.wait(this.mutex);
         }
      }
   }

   public final int size()
   {
      synchronized (mutex)
      {
         return queue.size();
      }
   }

   public final Object mutex()
   {
      return mutex;
   }

   public final void produce(T t)
   {
      synchronized (mutex)
      {
         queue.addLast(t);

         if (this.doNotifyAll)
            mutex.notifyAll();
         else
            mutex.notify();
      }
   }

   public final void produceFirst(T t)
   {
      synchronized (mutex)
      {
         queue.addFirst(t);

         if (this.doNotifyAll)
            mutex.notifyAll();
         else
            mutex.notify();
      }
   }

   public final List<T> drain()
   {
      synchronized (mutex)
      {
         List<T> list = new ArrayList<T>();
         while (!queue.isEmpty())
            list.add(queue.removeFirst());
         return list;
      }
   }

   public final T consume()
   {
      synchronized (mutex)
      {
         while (queue.isEmpty())
         {
            HighLevel.wait(this.mutex);
         }

         return queue.removeFirst();
      }
   }

   public final T consume(long milliTimeout)
   {
      synchronized (mutex)
      {
         long began = System.currentTimeMillis();

         while (queue.isEmpty())
         {
            long elapsed = System.currentTimeMillis() - began;
            if (elapsed > milliTimeout)
               return null;

            HighLevel.wait(this.mutex, Math.max(1, milliTimeout / 3));
         }

         return queue.removeFirst();
      }
   }

   public final T peek()
   {
      synchronized (mutex)
      {
         if (queue.isEmpty())
            return null;
         return queue.getFirst();
      }
   }

   public final T poll()
   {
      synchronized (mutex)
      {
         if (queue.isEmpty())
            return null;
         return queue.removeFirst();
      }
   }
}
