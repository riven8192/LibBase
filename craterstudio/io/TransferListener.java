/*
 * Created on 16-mei-2005
 */
package craterstudio.io;

import java.io.IOException;

public interface TransferListener
{
   public void transferInitiated(int expectedBytes);

   public void transfered(int bytes);

   public void transferFinished(IOException potentialException);
}