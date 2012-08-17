/*
 * Created on Jul 26, 2010
 */

package craterstudio.util.concur;

import java.util.logging.Level;
import java.util.logging.Logger;

import craterstudio.time.Clock;

public abstract class ResourceTransaction<R>
{
   private static final Logger   logger = Logger.getLogger(ResourceTransaction.class.getName());

   protected final R             resource;
   private volatile boolean      isLocked;
   private final long            startTime;
   private long                  finishTime;
   private final OneThreadAccess safeguard;

   public ResourceTransaction(R resource)
   {
      this.resource = resource;
      this.isLocked = true;
      this.startTime = Clock.now();
      this.finishTime = -1;
      this.safeguard = new OneThreadAccess();
   }

   public R getResource()
   {
      this.safeguard.check();
      
      return this.resource;
   }

   public void rollback()
   {
      this.safeguard.check();
      
      logger.log(Level.INFO, "tx.rollback not supported yet");
   }

   public void commit()
   {
      this.safeguard.check();
      
      logger.log(Level.INFO, "commit not supported yet");
   }

   public void finished()
   {
      this.safeguard.check();
      if (this.isFinished())
      {
         throw new IllegalStateException("transaction already finished");
      }
      this.isLocked = false;

      this.finishTime = Clock.now();

      logger.log(Level.FINE, "tx took: {0}ms", Long.valueOf(this.getDuration()));

      this.free();
   }

   protected abstract void free();

   public boolean isFinished()
   {
      return !this.isLocked;
   }

   public long getDuration()
   {
      return this.finishTime - this.startTime;
   }

   @Override
   protected void finalize() throws Throwable
   {
      if (this.isLocked)
      {
         throw new IllegalStateException("transaction was not finished");
      }
   }
}