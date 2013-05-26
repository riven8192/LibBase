/*
 * Created on Sep 3, 2008
 */

package craterstudio.util.concur;

import javax.swing.SwingUtilities;

public class RunnablePipelineOnEDT implements Runnable
{
   private final ConcurrentQueue<Task> pending;

   public RunnablePipelineOnEDT()
   {
      this.pending = new ConcurrentQueue<Task>(false);

      new Thread(this).start();
   }

   public Future<Long> enqueue(Runnable task)
   {
      return this.enqueueImpl(new Task(task, false));
   }

   public Future<Long> enqueueOnEDT(Runnable task)
   {
      Future<Long> took = this.enqueueImpl(new Task(task, true));

      // wait for potential triggered events

      task = new Runnable()
      {
         @Override
         public void run()
         {
            // dummy
         }
      };

      this.enqueueImpl(new Task(task, true));

      return took;
   }

   private Future<Long> enqueueImpl(Task task)
   {
      this.pending.produce(task);
      if (task == null)
         return null;
      return task.future;
   }

   public void finish()
   {
      this.enqueueImpl(null);
   }

   @Override
   public void run()
   {
      Task task;

      while ((task = this.pending.consume()) != null)
      {
         try
         {
            if (task.runOnEDT)
            {
               SwingUtilities.invokeLater(task);
               task.future.get();
            }
            else
            {
               task.run();
            }
         }
         catch (Throwable t)
         {
            t.printStackTrace();
         }
      }
   }

   private class Task implements Runnable
   {
      public final Runnable            task;
      public final boolean             runOnEDT;
      public final Future<Long> future;

      public Task(Runnable task, boolean runOnEDT)
      {
         this.task = task;
         this.runOnEDT = runOnEDT;
         this.future = new Future<Long>();
      }

      @Override
      public void run()
      {
         long t0 = System.currentTimeMillis();
         this.task.run();
         long t1 = System.currentTimeMillis();
         this.future.set(Long.valueOf(t1 - t0));
      }
   }
}
