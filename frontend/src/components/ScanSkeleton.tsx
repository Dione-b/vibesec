import Skeleton from "react-loading-skeleton";

interface ScanSkeletonProps {
  target: string;
}

export default function ScanSkeleton({ target }: ScanSkeletonProps) {
  return (
    <div className="w-full max-w-2xl mx-auto">
      <p className="text-text font-medium text-center text-base sm:text-lg break-all px-2 mb-6">
        {target}
      </p>

      <div className="space-y-3">
        <Skeleton height={80} borderRadius={12} />
        <Skeleton height={80} borderRadius={12} />
        <Skeleton height={80} borderRadius={12} />
        <div className="w-3/4 mx-auto">
          <Skeleton height={56} borderRadius={12} />
        </div>
      </div>
    </div>
  );
}
