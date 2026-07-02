import Skeleton from "react-loading-skeleton";

export function ReportPageSkeleton() {
  return (
    <div className="max-w-5xl mx-auto px-4 py-8 w-full">
      <div className="flex flex-wrap gap-2 mb-3">
        <Skeleton width={80} height={28} borderRadius={999} />
        <Skeleton width={72} height={28} borderRadius={999} />
      </div>
      <Skeleton width="70%" height={28} className="mb-2" />
      <Skeleton width="45%" height={14} className="mb-8" />

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 sm:gap-4 mb-8">
        <Skeleton height={80} borderRadius={16} />
        <Skeleton height={80} borderRadius={16} />
        <Skeleton height={80} borderRadius={16} />
      </div>

      <ReportContentSkeleton />
    </div>
  );
}

export function ReportContentSkeleton() {
  return (
    <>
      <Skeleton height={72} borderRadius={16} className="mb-6" />
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3 mb-8">
        <Skeleton height={100} borderRadius={16} />
        <Skeleton height={100} borderRadius={16} />
        <Skeleton height={100} borderRadius={16} />
        <Skeleton height={100} borderRadius={16} className="hidden sm:block" />
        <Skeleton height={100} borderRadius={16} className="hidden lg:block" />
      </div>
      <Skeleton width={240} height={44} borderRadius={16} className="mb-6 max-w-full" />
      <div className="space-y-4">
        <Skeleton height={140} borderRadius={16} />
        <Skeleton height={160} borderRadius={16} />
        <Skeleton height={120} borderRadius={16} />
      </div>
    </>
  );
}
