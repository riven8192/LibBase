/*
 * Created on 17 dec 2009
 */

package craterstudio.util.concur;

public interface ReadWriteTask<R, O>
{
   public O execute(R resource);
}