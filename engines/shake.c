/*
 * shake engine
 *
 * IO engine using Shake's libshake to test Shake Block Devices.
 *
 */

#include <shake.h>

#include "../fio.h"

struct fio_shake_iou {
    struct io_u *io_u;
    struct img_iocb_t iocb;
};

struct shake_data {
    struct img_t *img;
    struct img_iocb_t **iocbs;
};

struct shake_options {
	void *pad;
	char *shake_image_name;
	char *shake_pool_name;
	char *shake_client_name;
};

static struct fio_option options[] = {
	{
		.name		= "shake_image_name",
		.lname		= "shake engine image name",
		.type		= FIO_OPT_STR_STORE,
		.help		= "image name for shake engine",
		.off1		= offsetof(struct shake_options, shake_image_name),
		.category	= FIO_OPT_C_ENGINE,
		.group		= FIO_OPT_G_SHAKE,
	},
	{
		.name		= "shake_pool_name",
		.lname		= "shake engine pool",
		.type		= FIO_OPT_STR_STORE,
		.help		= "Name of the pool hosting the shake for the shake engine",
		.off1		= offsetof(struct shake_options, shake_pool_name),
		.category	= FIO_OPT_C_ENGINE,
		.group		= FIO_OPT_G_SHAKE,
	},
	{
		.name		= "shake_client_name",
		.lname		= "shake engine clientname",
		.type		= FIO_OPT_STR_STORE,
		.help		= "Name of the shake client to access the shake for the shake engine",
		.off1		= offsetof(struct shake_options, shake_client_name),
		.category	= FIO_OPT_C_ENGINE,
		.group		= FIO_OPT_G_SHAKE,
	},
	{
		.name = NULL,
	},
};



static struct io_u *fio_shake_event(struct thread_data *td, int event)
{
	struct shake_data *shake = td->io_ops->data;
    struct img_iocb_t *iocb = shake->iocbs[event];
    struct fio_shake_iou *shake_iou = container_of(iocb, struct fio_shake_iou, iocb);
    return shake_iou->io_u;
}




static int fio_shake_getevents(struct thread_data *td, unsigned int min,
			     unsigned int max, const struct timespec *t)
{

    struct shake_data *shake = td->io_ops->data;
    int r, events = 0;

    do {
        r = img_io_poll(shake->img, min, shake->iocbs + events, t);
        events += r;
    } while(events < min);

    return events;
}


static int fio_shake_queue(struct thread_data *td, struct io_u *io_u)
{
    struct shake_data *shake = td->io_ops->data;
    struct img_t *img = shake->img;
    struct fio_shake_iou *fsi = io_u->engine_data;
    int r = -1;

    fio_ro_check(td, io_u);

    switch (io_u->ddir) {
        case DDIR_WRITE:
            img_io_prep_pwrite(&fsi->iocb, img, io_u->xfer_buf,
                    io_u->xfer_buflen, io_u->offset, NULL);
            break;
        case DDIR_READ:
            img_io_prep_pread(&fsi->iocb, img, io_u->xfer_buf,
                    io_u->xfer_buflen, io_u->offset, NULL);
            break;
        case DDIR_TRIM:
            log_err("shake engine dont support trim comman.\n");
            dprint(FD_IO, "%s: Warning: unhandled ddir: %d\n", __func__,
                io_u->ddir);
            goto failed;
            break;
        case DDIR_SYNC:
            log_err("shake engine dont support sync comman.\n");
            dprint(FD_IO, "%s: Warning: unhandled ddir: %d\n", __func__,
                io_u->ddir);
            goto failed;
            break;
        default:
            dprint(FD_IO, "%s: Warning: unhandled ddir: %d\n", __func__,
                io_u->ddir);
            goto failed;
    }

    img_iocb_t* iocb_pp[1] = {&fsi->iocb};
    img_io_submit(img, 1, iocb_pp);
    return FIO_Q_QUEUED;

failed:
	io_u->error = r;
	td_verror(td, io_u->error, "xfer");
	return FIO_Q_COMPLETED;
}


static int fio_shake_init(struct thread_data *td)
{
    /* struct shake_options *o = td->eo; */
	/* struct shake_data *shake = td->io_ops->data; */
    /* struct img_t *img = img_open(o->shake_image_name, 0, IO_POLL_MODE); */
    /* if (img == NULL) { */
    /*     log_err("fio open shake image failed\n"); */
    /*     img_close(img); */
    /*     return -2; */
    /* } */
    /* shake->img = img; */
    return 0;
}

static int _fio_setup_shake_data(struct thread_data *td,
			       struct shake_data **shake_data_ptr)
{
	struct shake_data *shake;

	if (td->io_ops->data)
		return 0;

	shake = calloc(1, sizeof(struct shake_data));
	if (!shake)
		goto failed;

    shake->img = NULL;

	shake->iocbs = calloc(td->o.iodepth, sizeof(struct img_iocb_t *));
	if (!shake->iocbs)
		goto failed;

	*shake_data_ptr = shake;
	return 0;

failed:
	if (shake)
		free(shake);
	return 1;
}

static void fio_shake_cleanup(struct thread_data *td)
{
	struct shake_data *shake = td->io_ops->data;
    if (shake) {
        if (shake->iocbs) {
            free(shake->iocbs);
            shake->iocbs = NULL;
        }
        free(shake);
        td->io_ops->data = NULL;
    }
}


static int fio_shake_setup(struct thread_data *td)
{
    int major, minor, extra;
    major = 123456;
    minor = 654321;
    extra = 0;
    //libshake_version(&major, &minor, &extra);
    log_info("shake engine: libshake version: %d.%d.%d\n", major, minor, extra);

    if (td->o.numjobs > 1) {
        log_err("fio shake engine only support numjobs=1\n");
        return -1;
    }

    shake_enable();

    struct shake_data *shake = NULL;
	/* allocate engine specific structure to deal with libshake. */
	int r = _fio_setup_shake_data(td, &shake);
	if (r) {
		log_err("fio_setup_shake_data failed.\n");
		goto cleanup;
	}
	td->io_ops->data = shake;

    struct shake_options *o = td->eo;
    struct img_t *img = img_open(o->shake_image_name, 0, IO_POLL_MODE);
    if (img == NULL) {
        log_err("fio open shake image failed\n");
        goto close;
    }


	/* libshake does not allow us to run first in the main thread and later
	 * in a fork child. It needs to be the same process context all the
	 * time. 
	 */
    td->o.use_thread = 1;

    img->size = 100*1024*1024; // NOTE TODO
	dprint(FD_IO, "shake-engine: image size: %lu\n", img->size);

	/* taken from "net" engine. Pretend we deal with files,
	 * even if we do not have any ideas about files.
	 * The size of the Shake is set instead of a artificial file.
	 */
	struct fio_file *f;
	if (!td->files_index) {
		add_file(td, td->o.filename ? : "shake", 0, 0);
		td->o.nr_files = td->o.nr_files ? : 1;
		td->o.open_files++;
	}
	f = td->files[0];
	f->real_file_size = img->size;

    shake->img = img;
    //img_close(img);
	return 0;

close:
    //img_close(img);
cleanup:
    fio_shake_cleanup(td);
    return r;
}


static int fio_shake_open(struct thread_data *td, struct fio_file *f)
{
	return 0;
}


static int fio_shake_invalidate(struct thread_data *td, struct fio_file *f)
{
    //TODO
    return 0;
}

static void fio_shake_io_u_free(struct thread_data *td, struct io_u *io_u)
{
	struct fio_shake_iou *fri = io_u->engine_data;

	if (fri) {
		io_u->engine_data = NULL;
		free(fri);
	}
}

static int fio_shake_io_u_init(struct thread_data *td, struct io_u *io_u)
{
	struct fio_shake_iou *fri;

	fri = calloc(1, sizeof(*fri));
	fri->io_u = io_u;
	io_u->engine_data = fri;
	return 0;
}

static struct ioengine_ops ioengine = {
	.name			= "shake",
	.version		= FIO_IOOPS_VERSION,
	.setup			= fio_shake_setup,
	.queue			= fio_shake_queue,
	.getevents		= fio_shake_getevents,
	.event			= fio_shake_event,
	.cleanup		= fio_shake_cleanup,
	.open_file		= fio_shake_open,
	.invalidate		= fio_shake_invalidate,
	.options		= options,
	.io_u_init		= fio_shake_io_u_init,
	.io_u_free		= fio_shake_io_u_free,
	.option_struct_size	= sizeof(struct shake_options),
};

static void fio_init fio_shake_register(void)
{
	register_ioengine(&ioengine);
}

static void fio_exit fio_shake_unregister(void)
{
	unregister_ioengine(&ioengine);
}
