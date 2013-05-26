/*
 * Created on 1 dec 2009
 */

package craterstudio.io;

import java.io.File;

public interface DirectoryVisitor
{
   public void visit(File parent, String name);
}
