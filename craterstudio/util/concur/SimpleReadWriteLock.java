/*
 * Created on 19 aug 2010
 */

package craterstudio.util.concur;

import java.util.concurrent.locks.ReentrantReadWriteLock;

public class SimpleReadWriteLock
{
   private final ReentrantReadWriteLock backing;

   public SimpleReadWriteLock()
   {
      this.backing = new ReentrantReadWriteLock();
   }

   public SimpleReadWriteLock(boolean forWriting)
   {
      this();

      if (forWriting)
         this.beginWrite();
      else
         this.beginRead();
   }

   //

   public boolean hasReadAccess()
   {
      return this.hasWriteAccess() || this.backing.getReadHoldCount() > 0;
   }

   public boolean hasWriteAccess()
   {
      return this.backing.isWriteLockedByCurrentThread();
   }

   //

   public void checkAccess(boolean forWriting)
   {
      if (forWriting)
         this.checkWriteAccess();
      else
         this.checkReadAccess();
   }

   public void checkReadAccess()
   {
      if (!this.hasReadAccess())
         throw new IllegalThreadStateException();
   }

   public void checkWriteAccess()
   {
      if (!this.hasWriteAccess())
         throw new IllegalThreadStateException();
   }

   //

   public void beginRead()
   {
      if (this.hasReadAccess())
         return;

      this.backing.readLock().lock();
   }

   public void beginWrite()
   {
      if (this.hasWriteAccess())
         return;

      if (this.hasReadAccess())
         throw new IllegalStateException("cannot aquire write-lock when read-lock is held");

      this.backing.writeLock().lock();
   }

   //

   public void finish()
   {
      while (this.backing.getReadHoldCount() > 0)
         this.backing.readLock().unlock();

      while (this.backing.getWriteHoldCount() > 0)
         this.backing.writeLock().unlock();
   }
}
