/**
 * @file time.c
 * @author andyhhp
 * @brief Domain time management
 *
 * This functions has been defined:
 *
 * - sys_open
 * - fdesc_init
 * - sys_read
 * - sys_write
 * - sys_dup2
 * - sys_chdir
 * - sys_lseek
 * - sys_close
 * - sys___getcwd
 *
 * @version 0.1
 * @date 2021-26-06
 *
 */

#include <types.h>
#include <lib.h>
#include <synch.h>
#include <array.h>
#include <vfs.h>
#include <vnode.h>
#include <fs.h>
#include <uio.h>
#include <device.h>
#include <kern/limits.h>
#include <kern/unistd.h>
#include <kern/errno.h>
#include <thread.h>
#include <current.h>
#include <file.h>
#include <kern/fcntl.h>
#include <copyinout.h>
#include <kern/seek.h>
#include <file.h>
#include <limits.h>
#include <kern/stat.h>
#include <spl.h>
#include <current.h>

//struct File *fp[20];
//fp=(struct File*)malloc(sizeof(struct File));
//fp->open=true;


/* a simple init function for testing the file functions*/

//struct File *fdesc[20];

struct vnode* get_filetab(int fd) {
	return curthread->fdesc[fd]->vnode;
}

/**
* @brief open or creat file with filename
*
*	@param[in] filename
*	@param[in] flags
*	@param[in] mode
*	@param[out] retval: pointer to int
*
* @return int
*
*/
int sys_open(const_userptr_t filename, int flags, int mode, int *retval){

  	int result,fd;
	struct stat tmp;
	size_t len;
	struct vnode *vn; ///<abstract structure for an on-disk file (vnode.h)

	/**
	* check input parameter
	* \b flags will check automatic in vfs_open
	*/
	if (filename == NULL) {
		return EFAULT;
	}

	///allocate kernel space for file name
	char *fname = (char*)kmalloc(sizeof(char)*PATH_MAX);
	if(fname == NULL)
		return ENOMEM;
	///copy the filename string to kernel space
	copyinstr(filename, fname, PATH_MAX, &len);

	///find free filedescriptor after stderr
  	for(fd = 3; fd < MAX_FILE_FILETAB; fd++)
	{
    		if(curthread->fdesc[fd] == NULL)
			break;
	}
	///detecting end files
	if(fd == MAX_FILE_FILETAB)
	{
		return ENFILE;
	}
  	curthread->fdesc[fd] = (struct File *)kmalloc(sizeof(struct File*));
	if(curthread->fdesc[fd] == NULL)
	{
        	return ENFILE;
  	}
	  /**
		* vfs_open
		* @bief Open or create a file. FLAGS/MODE per the syscall.
		*/
  	result = vfs_open(fname, flags,mode, &vn);
	curthread->fdesc[fd]->vnode = vn;
	if(result)
    		return result;

	/// - Initialize fdesc structure
	curthread->fdesc[fd]->flags = flags;///save given flags to fdesc flags

	if(flags!=O_APPEND)
		curthread->fdesc[fd]->offset = 0;///set seek pointer on top of the file
	else{
		result = VOP_STAT(curthread->fdesc[fd]->vnode, &tmp);
		if(result)
				return -1;
	curthread->fdesc[fd]->offset = tmp.st_size; ///set seek pointer on end of the file
	}

	curthread->fdesc[fd]->f_lock=lock_create(fname);
	*retval = fd;///save file filedescriptor in retval
	kfree(fname);///free the kernel space allocated for file name
	return 0;///return on success
}

/**
* @brief initialize consoll file filedescriptor for new thread
*
*	@param[in] newthread: pointer to thread struct
*
* @return int
*
*/
int fdesc_init(struct thread *newthread)
{
	if(newthread->fdesc[0] == NULL){ // check the index 0 of fdesc in empty
	int result1;
	struct vnode *v1;
	newthread->fdesc[0] = (struct File *)kmalloc(sizeof(struct File)); // allocate kernel space for this fd
	char temp1[]="con:"; // inorder to this spectioal fd (stdin) our fd_name is consoll
	result1 = vfs_open(temp1, O_RDONLY, 0664, &v1);// open stdin file descriptor
	// if can't open it return error
	if(result1){
		kprintf("fdesc_init failed\n");
		kfree(temp1);
		return EINVAL;
	}
	// set fdesc parameter for stdin
	newthread->fdesc[0]->vnode = v1;
	newthread->fdesc[0]->flags = O_RDONLY;
	newthread->fdesc[0]->offset = 0;
	newthread->fdesc[0]->f_lock = lock_create(temp1);
	}

	if(newthread->fdesc[1] == NULL){
	struct vnode *v2;
	newthread->fdesc[1] = (struct File *)kmalloc(sizeof(struct File));
	char temp2[]="con:";
	int result2 = vfs_open(temp2, O_WRONLY, 0664, &v2);
	if(result2) {
		kprintf("fdesc_init failed\n");
		kfree(temp2);
		return EINVAL;
	}
	// set fdesc parameter for stdout
	newthread->fdesc[1]->vnode=v2;
	newthread->fdesc[1]->flags = O_WRONLY;
	newthread->fdesc[1]->offset = 0;
	newthread->fdesc[1]->f_lock = lock_create(temp2);
	}

	if(newthread->fdesc[2] == NULL){
	struct vnode *v3;
	newthread->fdesc[2] = (struct File *)kmalloc(sizeof(struct File));
	char temp3[]="con:";
	int result3 = vfs_open(temp3, O_WRONLY, 0664, &v3);
	if(result3) {
		kprintf("fdesc_init failed\n");
		kfree(temp3);
		return EINVAL;
	}
	// set fdesc parameter for stderr
	newthread->fdesc[2]->vnode = v3;
	newthread->fdesc[2]->flags = O_WRONLY;
	newthread->fdesc[2]->offset=0;
	newthread->fdesc[2]->f_lock = lock_create(temp3);
	}
	return 0;
}

 /**
 * @brief read an opened file with file handle to a buffer of specified size
 *
 *	@param[in] filehandle : represent file filedescriptor
 *	@param[in] buf
 *	@param[in] size
 *	@param[out] retval: pointer to int
 *
 * @return int
 *
 */
int sys_read(int filehandle, void *buf, size_t size,int* retval){


  lock_acquire(curthread->fdesc[filehandle]->f_lock);/// - Lock filedescriptor for multithreading programs

	///check filehandle validity
	if(filehandle < 0 || filehandle > MAX_FILE_FILETAB){
		*retval = -1;
		return EBADF;
	}
	if(curthread->fdesc[filehandle] == NULL)
	{
		*retval = -1;
		return EBADF;
	}
	/// part or all af address space pointed to by buf is invallid
	if(buf == NULL){
		*retval=-1;
		return EFAULT;
	}
	///check file's permission
	if(! (curthread->fdesc[filehandle]->flags != O_RDONLY && curthread->fdesc[filehandle]->flags != O_RDWR) )
	{
		*retval = -1;
		return EINVAL;
	}

	struct uio readuio;
	struct iovec iov;
	char *buffer = (char*)kmalloc(size);
	//readuio = (struct uio*)kmalloc(sizeof(struct uio));

	/* Initialize a uio suitable for I/O from a kernel buffer.*/
 	uio_kinit(&iov,&readuio,(void*)buffer,size,curthread->fdesc[filehandle]->offset,UIO_READ);

    /**
	* @brief    vop_read  - Read data from file to uio, at offset specified
	*                       in the uio, updating uio_resid to reflect the
	*                       amount read, and updating uio_offset to match.
	*                       Not allowed on directories or symlinks.
	*
	*/
  int result=VOP_READ(curthread->fdesc[filehandle]->vnode, &readuio);
	if (result) {
		kfree(buffer);
		lock_release(curthread->fdesc[filehandle]->f_lock);
	    *retval = -1;
        return result;
	}
	//if(filehandle > 3)
  	curthread->fdesc[filehandle]->offset= readuio.uio_offset;
	//else
	//copyoutstr((const char*)buffer,(userptr_t)buf,sizeof(buffer),&size1);
	//	curthread->fdesc[filehandle]->offset= 1;

	/**
	* @brief   copyout copies LEN bytes from a kernel-space address SRC to a
  	* 		   user-space address USERDEST.
	*
	*
	*/
	copyout((const void *)buffer, (userptr_t)buf, size);
    *retval=size - readuio.uio_resid; /// - uio->uio_resid is how many bytes left after the IO operation
	kfree(buffer);
	//kfree(readuio->uio_iov);
    //kfree(readuio);
	lock_release(curthread->fdesc[filehandle]->f_lock);
	return 0;
}

/**
 * @brief write to a filehandle from a buffer of specified size
 *
 *
 */
int sys_write(int filehandle,void *buf, size_t size,int* retval){

  /// check filehandle validity
	if(filehandle < 0 || filehandle > MAX_FILE_FILETAB){
		*retval = -1;
		return EBADF;
	}
	if(curthread->fdesc[filehandle] == NULL)
	{
		*retval = -1;
		return EBADF;
	}
	if(! (curthread->fdesc[filehandle]->flags != O_WRONLY && curthread->fdesc[filehandle]->flags!=O_RDWR) )
	{
		*retval = -1;
		return EINVAL;
	}
	lock_acquire(curthread->fdesc[filehandle]->f_lock);

	struct uio writeuio;
	struct iovec iov;
	size_t size1;
	char *buffer = (char*)kmalloc(size);

	/**
	* @brief  copyinstr copies a null-terminated string of at most LEN bytes from
    * 				a user-space address USERSRC to a kernel-space address DEST, and
    * 				returns the actual length of string found in GOT. DEST is always
    * 				null-terminated on success. LEN and GOT include the null terminator.
	*
	*/
	copyinstr((userptr_t)buf,buffer,strlen(buffer),&size1);

    /* Initialize a uio suitable for I/O from a kernel buffer.*/
	uio_kinit(&iov, &writeuio, (void*) buffer, size, curthread->fdesc[filehandle]->offset, UIO_WRITE);

	/**
	* @brief   vop_write   - Write data from uio to file at offset specified
    *                      in the uio, updating uio_resid to reflect the
    *                      amount written, and updating uio_offset to match.
    *                      Not allowed on directories or symlinks.
	*
	*/
	int result=VOP_WRITE(curthread->fdesc[filehandle]->vnode, &writeuio);
  if (result) {
		kfree(buffer);
		lock_release(curthread->fdesc[filehandle]->f_lock);
		*retval = -1;
        return result;
  }
	curthread->fdesc[filehandle]->offset = writeuio.uio_offset;
	*retval = size - writeuio.uio_resid;/// - uio->uio_resid is how many bytes left after the IO operation
	kfree(buffer);
	lock_release(curthread->fdesc[filehandle]->f_lock);
    return 0;
}

/*
 * @brief close a file using filehandle
 *
 *	@param[in] filehandle
 *	@param[out] retval: pointer to int
 *
 * @return int
 * 				\b 0 on success
 */
int sys_lseek(int filehandle, off_t pos, int code,int *retval){

	off_t offset;
	struct stat tmp;
	int result;

	if(filehandle < 0 || filehandle > MAX_FILE_FILETAB){
		*retval = -1;
		return EBADF;
	}
	if(curthread->fdesc[filehandle] == NULL)
	{
		*retval = -1;
		return EBADF;
	}
	struct File* fd = curthread->fdesc[filehandle];
	lock_acquire(fd->f_lock);

	//actual seek occurs
	switch(code) {
		case SEEK_SET://SEEK_SET – It moves file pointer to the beginning of the file and then apllye position
		offset = pos;
		break;

		case SEEK_CUR://SEEK_CUR – It moves file pointer to given location and then apllye position
		offset = fd->offset + pos;
		break;

		case SEEK_END://SEEK_END – It moves file pointer to the end of file and then apllye position
      		result = VOP_STAT(fd->vnode, &tmp);/// use this in order to rich file size
		if(result){
			lock_release(curthread->fdesc[filehandle]->f_lock);
        	return result;
		}
		offset = tmp.st_size + pos;
		break;

		default:
		lock_release(curthread->fdesc[filehandle]->f_lock);
		return EINVAL;
	}

	if(offset < 0) {
		lock_release(curthread->fdesc[filehandle]->f_lock);
		return EINVAL;
	}

    /**
	* @brief vop_tryseek   - Check if seeking to the specified position within
	*                      the file is legal. (For instance, all seeks
	*                      are illegal on serial port devices, and seeks
	*                      past EOF on files whose sizes are fixed may be
	*                      as well.)
	*/
	result = VOP_TRYSEEK(fd->vnode, offset);
	if(result){
		lock_release(curthread->fdesc[filehandle]->f_lock);
		return result;
	}

	// All done, update offset
	*retval = fd->offset = offset;
	lock_release(curthread->fdesc[filehandle]->f_lock);
	return 0;
}

/**
 * @brief close a file using filehandle
 *
 *	@param[in] filehandle
 *	@param[out] retval: pointer to int
 *
 * @return int
 * 				\b 0 on success
 */
int sys_close(int filehandle,int* retval){

///check filehandle validity
 	if(filehandle < 0 || filehandle > MAX_FILE_FILETAB){
		*retval = -1;
		return EBADF;
	}
	if(curthread->fdesc[filehandle] == NULL){
	    *retval = -1;
        return EBADF;
 	 }
	/// - Lock filedescriptor for multithreading progams
	lock_acquire(curthread->fdesc[filehandle]->f_lock);

    ///close the file using vfs_close
	if(curthread->fdesc[filehandle]->vnode != NULL)
		vfs_close(curthread->fdesc[filehandle]->vnode);

	///free the struct fdesc if the counter reaches 0
	if(curthread->fdesc[filehandle]->vnode->vn_refcount == 0) {
		if(curthread->fdesc[filehandle]->vnode != NULL)
			kfree(curthread->fdesc[filehandle]->vnode);
		kfree(curthread->fdesc[filehandle]);
	}

	else {
		///decrease the file reference counter
        curthread->fdesc[filehandle] = NULL;
	}
  *retval = 0;
  lock_release(curthread->fdesc[filehandle]->f_lock);   /// - Unlock filedescriptor
  return 0;
}

/**
 * @brief clone the filehandle in newhandle
 *
 *	@param[in] filehandle
 *	@param[in] newhandle
 *	@param[out] retval: pointer to int
 *
 * @return int
 * 				\b 0 on success
 */
int sys_dup2(int filehandle, int newhandle, int* retval){
        if(filehandle < 0 || newhandle < 0){
          *retval = -1;
                return EBADF;
        }
        if(filehandle >= MAX_FILE_FILETAB || newhandle >= MAX_FILE_FILETAB){
           *retval = -1;
           return EBADF;
        }
     /*   if(curthread->fdesc[newhandle] != NULL){
                if(sys_close(filehandle,retval))
                	return EBADF;
        }
	*/
	lock_acquire(curthread->fdesc[filehandle]->f_lock);
        curthread->fdesc[newhandle]->flags = curthread->fdesc[filehandle]->flags;
        curthread->fdesc[newhandle]->offset = curthread->fdesc[filehandle]->offset;
        curthread->fdesc[newhandle]->vnode = curthread->fdesc[filehandle]->vnode;
	*retval = newhandle;
	lock_release(curthread->fdesc[filehandle]->f_lock);
    return 0;
}

/**
 * @brief get named of current networking directory
 *
 *	@param[out] fname: pointer to char
 *	@param[in]  buflen:
 *	@param[out] retval: pointer to int
 *
 * @return int
 * 				\b 0 on success
 */
int sys___getcwd(char *fname, size_t buflen, int *retval)
{

	/*
	 * iovec structure, used in the readv/writev scatter/gather I/O calls,
	 * and within the kernel for keeping track of blocks of data for I/O.
	 */
	struct iovec iov;
	struct uio readuio;

	char *name = (char*)kmalloc(buflen);

	/*
	 * @breif Initialize a uio suitable for I/O from a kernel buffer.
	 */
	uio_kinit(&iov, &readuio, name, buflen-1, 0, UIO_READ);

  /**
	* @breif  vfs_getcwd - Retrieve name of current directory of current thread.
	*/
	int result = vfs_getcwd(&readuio);
	if(result)
	{
		*retval = -1;
		return result;
	}
	///null terminate the name
	name[buflen-1-readuio.uio_resid] = 0;
	size_t size;

	/**
	* @breif copyoutstr copies a null-terminated string of at most LEN bytes from
	* 			 a kernel-space address SRC to a user-space address USERDEST, and
	* 			 returns the actual length of string found in GOT. DEST is always
	* 			 null-terminated on success. LEN and GOT include the null terminator.
	*/
	copyoutstr((const void *)name, (userptr_t)fname, buflen, &size);
	*retval = buflen-readuio.uio_resid;
	kfree(name);
	return 0;
}

/**
 * @brief The current directory of the current proccess is set to the directory named by fname
 *
 *	@param[in] fname: pointer to char
 *	@param[out] retval: pointer to int
 *
 * @return int
 * 				\b 0 on success
 */
int sys_chdir(char *fname, int *retval)
{
	char *name = (char*)kmalloc(sizeof(char)*PATH_MAX);
	size_t len;
	/**
	*      splhigh()  sets interrupt periority level to the highest value, disabling all interrupts.
	* Note that these function only affect interrupts on the current processor.
	*/
	int s = splhigh();

	/**
	* @breif copyinstr copies a null-terminated string of at most LEN bytes from
    * 			 a user-space address USERSRC to a kernel-space address DEST, and
    * 			 returns the actual length of string found in GOT. DEST is always
    * 			 null-terminated on success. LEN and GOT include the null terminator.
	*/
	copyinstr((userptr_t)fname, name, PATH_MAX, &len);

	/**
	* @breif vfs_chdir  - Change current directory of current thread by name.
	*/
	int result = vfs_chdir(name);
	if(result)
	{
		/**
		* @breif splx(s)  sets interrupt periority level to S, enabling whatever state S represents.
	    * Note that these function only affect interrupts on the current processor.
		*/
		splx(s);
		return result;
	}
	*retval = 0;
	kfree(name);
	splx(s);
	return 0;
}
