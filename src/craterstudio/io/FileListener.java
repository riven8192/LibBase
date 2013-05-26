/*
 * Created on Aug 9, 2005
 */
package craterstudio.io;

import java.io.File;

public interface FileListener
{
   public void fileCreated(File file);

   public void fileUpdating(File file);

   public void fileUpdated(File file);

   public void fileDeleted(File file, boolean wasDirectory);
}
