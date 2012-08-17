/*
 * Created on 19 mrt 2010
 */

package craterstudio.util.concur;

public class TaskFeedback<T>
{
   @SuppressWarnings("all")
   public void success(T t)
   {

   }

   @SuppressWarnings("all")
   public void failure(Exception exc)
   {
      exc.printStackTrace();
   }

   @SuppressWarnings("all")
   public void cleanup()
   {

   }
}