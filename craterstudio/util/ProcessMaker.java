/*
 * Created on 18 nov 2008
 */

package craterstudio.util;

import java.io.*;
import java.util.*;

import craterstudio.io.Streams;
import craterstudio.util.concur.Future;

public class ProcessMaker
{
   public static final int launchDefaultApplication(String argument)
   {
      try
      {
         String exec = "cmd /c \"start " + argument + "\"";
         Process p = Runtime.getRuntime().exec(exec);
         p.waitFor();
         return p.exitValue();
      }
      catch (Exception exc)
      {
         throw new IllegalStateException(exc);
      }
   }

   private List<String> cmds;
   private File         workdir;

   public ProcessMaker()
   {
      this.cmds = new ArrayList<String>();
      this.workdir = null;
   }

   public void setWorkingDirectory(File workdir)
   {
      this.workdir = workdir;
   }

   public void clearCommands()
   {
      this.cmds.clear();
   }

   public void addCommands(String... cmds)
   {
      for (String cmd : cmds)
         this.cmds.add(cmd);
   }

   public Future<Integer> start()
   {
      return this.start(System.out, System.err, false);
   }

   public Future<Integer> start(OutputStream out, OutputStream err, boolean closeStreamsOnExit)
   {
      final Future<Integer> future = new Future<Integer>();

      String[] cmds = this.cmds.toArray(new String[this.cmds.size()]);

      final Process p;

      try
      {
         p = Runtime.getRuntime().exec(cmds, null, this.workdir);
      }
      catch (Exception exc)
      {
         throw new IllegalStateException("cmds=" + Arrays.toString(cmds), exc);
      }

      Streams.asynchronousTransfer(p.getInputStream(), out, true, closeStreamsOnExit);
      Streams.asynchronousTransfer(p.getErrorStream(), err, true, closeStreamsOnExit);

      new Thread()
      {
         public void run()
         {
            int exitValue = -1;
            boolean exited = false;

            do
            {
               try
               {
                  p.waitFor();
               }
               catch (InterruptedException exc)
               {
                  // ignore
               }

               try
               {
                  exitValue = p.exitValue();
                  exited = true;
               }
               catch (IllegalThreadStateException exc)
               {
                  // ignore
               }
            }
            while (!exited);

            future.set(Integer.valueOf(exitValue));
         }
      }.start();

      return future;
   }
}
