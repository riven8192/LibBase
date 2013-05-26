/*
 * Created on 17 dec 2009
 */

package craterstudio.util.concur;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock.ReadLock;
import java.util.concurrent.locks.ReentrantReadWriteLock.WriteLock;
import java.util.logging.Level;
import java.util.logging.Logger;

public class ReadWritePool<R>
{
   private static final Logger          logger = Logger.getLogger(ReadWritePool.class.getName());

   private final ReentrantReadWriteLock lock;
   private final SimpleBlockingQueue<R> resources;
   private final int                    resourceCount;

   public ReadWritePool(R[] resources)
   {
      this(resources, true);
   }

   public ReadWritePool(R[] resources, boolean fair)
   {
      if (resources.length == 0)
      {
         throw new IllegalArgumentException("pool must have more at least one resource");
      }

      this.resourceCount = resources.length;
      this.lock = new ReentrantReadWriteLock(fair);
      this.resources = new SimpleBlockingQueue<R>(resources.length);

      for (R resource : resources)
      {
         if (resource == null)
            throw new NullPointerException();
         this.resources.put(resource);
      }
   }

   //

   public List<R> takeAll()
   {
      List<R> resources = new ArrayList<R>();
      for (int i = 0; i < this.resourceCount; i++)
         resources.add(this.aquireResource());
      return resources;
   }

   //

   public ResourceTransaction<R> aquireReadTransaction()
   {
      if (this.lock.getReadHoldCount() > 0)
         throw new IllegalThreadStateException("read lock already held");

      final ReadLock lock = this.lock.readLock();
      lock.lock();
      return new ResourceTransaction<R>(this.aquireResource())
      {
         @Override
         protected void free()
         {
            ReadWritePool.this.releaseResource(this.getResource());
            lock.unlock();
         }
      };
   }

   public ResourceTransaction<R> aquireWriteTransaction()
   {
      if (this.lock.isWriteLockedByCurrentThread())
         throw new IllegalThreadStateException("write lock already held");

      final WriteLock lock = this.lock.writeLock();
      lock.lock();
      return new ResourceTransaction<R>(this.aquireResource())
      {
         @Override
         protected void free()
         {
            ReadWritePool.this.releaseResource(this.getResource());
            lock.unlock();
         }
      };
   }

   //

   public <O, P> O readLock(ReadWriteTask<R, O> task)
   {
      R resource = this.aquireResource();

      this.lock.readLock().lock();

      try
      {
         return task.execute(resource);
      }
      finally
      {
         this.lock.readLock().unlock();

         this.releaseResource(resource);
      }
   }

   public <O, P> O writeLock(ReadWriteTask<R, O> task)
   {
      R resource = this.aquireResource();

      if (this.lock.getReadHoldCount() > 0)
         throw new IllegalStateException("already holding read lock");
      this.lock.writeLock().lock();

      try
      {
         return task.execute(resource);
      }
      finally
      {
         this.lock.writeLock().unlock();

         this.releaseResource(resource);
      }
   }

   public <O, P> O writeReadLock(ReadWriteTask<R, Void> write, ReadWriteTask<R, O> read)
   {
      R resource = this.aquireResource();

      this.lock.writeLock().lock();

      boolean downgraded = false;

      try
      {
         write.execute(resource);

         try
         {
            // downgrade
            this.lock.readLock().lock();
            this.lock.writeLock().unlock();
            downgraded = true;

            return read.execute(resource);
         }
         finally
         {
            this.lock.readLock().unlock();
         }
      }
      finally
      {
         if (!downgraded)
         {
            this.lock.writeLock().unlock();
         }

         this.releaseResource(resource);
      }
   }

   // impl

   private final ThreadLocal<List<R>> threadHeldResources = new ThreadLocal<List<R>>()
                                                          {
                                                             @Override
                                                             protected List<R> initialValue()
                                                             {
                                                                return new LinkedList<R>();
                                                             }
                                                          };

   private final R aquireResource()
   {
      R resource = this.resources.poll();
      if (resource == null)
      {
         logger.log(Level.FINE, "Resource not immediately available");
         resource = this.resources.take();
      }
      this.threadHeldResources.get().add(resource);
      return resource;
   }

   final void releaseResource(R resource)
   {
      if (!this.threadHeldResources.get().remove(resource))
         throw new IllegalStateException("released resource on wrong thread");
      this.resources.put(resource);
   }
}