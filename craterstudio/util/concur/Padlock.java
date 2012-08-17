/*
 * Created on 18-sep-2007
 */

package craterstudio.util.concur;

import craterstudio.util.HighLevel;

public class Padlock
{
   private volatile Key key   = null;
   private final Object mutex = new Object();

   /**
    * Waits for this lock to become unlocked (if necessary), and locks it.
    */

   public Key lock()
   {
      synchronized (this.mutex)
      {
         while (this.key != null)
         {
            HighLevel.wait(this.mutex);
         }

         return this.key = new Key();
      }
   }

   public Key tryLock()
   {
      synchronized (this.mutex)
      {
         if (this.key != null)
         {
            return null;
         }

         return this.key = new Key();
      }
   }

   public Object mutex()
   {
      return this.mutex;
   }

   public boolean isLocked()
   {
      synchronized (this.mutex)
      {
         return this.key != null;
      }
   }

   public void unlock(Key key)
   {
      synchronized (this.mutex)
      {
         if (key == null || this.key != key)
            throw new IllegalArgumentException("invalid key");

         this.key = null;
         this.mutex.notifyAll();
      }
   }

   public void forceUnlock()
   {
      synchronized (this.mutex)
      {
         this.unlock(this.key);
      }
   }

   public void waitFor()
   {
      this.unlock(this.lock());
   }

   public class Key
   {
      Key()
      {
         //
      }
   }
}