/*
 * Created on 8 mrt 2010
 */

package craterstudio.streams;

public enum MultipartType
{
   MIXED("multipart/mixed"), //
   RELATED("multipart/related"), //
   ALTERNATIVE("multipart/alternative"), // 
   X_MIXED_REPLACE("multipart/x-mixed-replace"), //
   ;

   public final String msg;

   private MultipartType(String message)
   {
      this.msg = message;
   }
}
