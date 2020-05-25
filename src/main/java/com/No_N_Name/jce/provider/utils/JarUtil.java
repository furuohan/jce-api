package com.No_N_Name.jce.provider.utils;

import java.io.File;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;


public class JarUtil {
	   private String jarName;
	   private String jarPath;

	   public JarUtil(Class clazz) {
	      String path = clazz.getProtectionDomain().getCodeSource().getLocation().getFile();

	      try {
	         path = URLDecoder.decode(path, "UTF-8");
	      } catch (UnsupportedEncodingException var5) {
	         var5.printStackTrace();
	      }

	      File jarFile = new File(path);
	      this.jarName = jarFile.getName();
	      File parent = jarFile.getParentFile();
	      if (parent != null) {
	         this.jarPath = parent.getAbsolutePath();
	      }

	   }

	   public String getJarName() {
	      try {
	         return URLDecoder.decode(this.jarName, "UTF-8");
	      } catch (UnsupportedEncodingException var2) {
	         var2.printStackTrace();
	         return null;
	      }
	   }

	   public String getJarPath() {
	      try {
	         return URLDecoder.decode(this.jarPath, "UTF-8");
	      } catch (UnsupportedEncodingException var2) {
	         var2.printStackTrace();
	         return null;
	      }
	   }

	   public static void main(String[] args) throws Exception {
	      JarUtil ju = new JarUtil(JarUtil.class);
	      System.out.println("Jar name: " + ju.getJarName());
	      System.out.println("Jar path: " + ju.getJarPath());
	   }
}
