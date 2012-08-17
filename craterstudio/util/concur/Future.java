/*
 * Created on Nov 16, 2008
 */

package craterstudio.util.concur;

import java.util.concurrent.TimeoutException;

public class Future<T>
{
   private final SimpleCountDownLatch latch;
   private T                          result;
   private Throwable                  error;

   public Future()
   {
      this.latch = new SimpleCountDownLatch();
      this.result = null;
      this.error = null;
   }

   public boolean isDone()
   {
      return this.latch.isDone();
   }

   public T peek()
   {
      if (!this.latch.isDone())
         return null;

      this.checkForError();

      return this.result;
   }

   public T get()
   {
      this.latch.await();

      this.checkForError();

      return this.result;
   }

   public T get(long ms) throws TimeoutException
   {
      if (!this.latch.await(ms))
         throw new TimeoutException();

      this.checkForError();

      return this.result;
   }

   public void set(T result)
   {
      this.result = result;

      this.latch.countDown();
   }

   public void error(Exception error)
   {
      if (error == null)
         throw new NullPointerException();

      this.error = error;
      
      this.latch.countDown();
   }

   private void checkForError()
   {
      Throwable error = this.error;
      if (error == null)
         return;
      throw new IllegalStateException("error occured", error);
   }
}